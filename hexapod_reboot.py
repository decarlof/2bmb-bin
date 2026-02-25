#!/usr/bin/env python3
"""
Usage
-----

Reboot hexapod controller (power-cycled via PDU outlet 5) and restart its EPICS IOC.

Prereqs:
  - Credentials file exists: ~/access.json
      Must contain keys:
        pdu_a_ip_address, pdu_a_username, pdu_a_password
        pdu_b_ip_address, pdu_b_username, pdu_b_password
      (webcam_* keys may also be present; they are ignored)

  - You can SSH to the IOC host without interactive password prompts
      ssh 2bmb@arcturus

  - EPICS command-line tools available on the machine running this script:
      caget, caput

Examples:
  # Reboot using default PDU "a"
  python reboot_hexapod.py

  # Reboot using PDU "b"
  python reboot_hexapod.py --pdu b
"""

import argparse
import base64
import http.client
import json
import os
import pathlib
import re
import socket
import subprocess
import time

CREDENTIALS_FILE_NAME = os.path.join(str(pathlib.Path.home()), "access.json")

# Start/stop IOC via helper scripts (in PATH)
IOC_START_SCRIPT = "hexapod_IOC.sh"
IOC_STOP_SCRIPT  = "hexapod_IOC_stop.sh"

PV_ALL_ENABLED = "2bmHXP:HexapodAllEnabled.VAL"
PV_ENABLE_WORK = "2bmHXP:EnableWork.PROC"

HEXAPOD_OUTLET = 5

# Hexapod controller network details for readiness check
# Adjust these to match your hexapod controller's IP and command port
HEXAPOD_CONTROLLER_IP   = None   # Set below from args or config
HEXAPOD_CONTROLLER_PORT = 5001   # Default XPS-C8/D command port


def load_pdu_creds(pdu: str):
    pdu = pdu.lower()
    if pdu not in ("a", "b"):
        raise ValueError("--pdu must be 'a' or 'b'")

    with open(CREDENTIALS_FILE_NAME, "r") as f:
        cfg = json.load(f)

    prefix = f"pdu_{pdu}_"
    ip = cfg[prefix + "ip_address"]
    user = cfg[prefix + "username"]
    pwd = cfg[prefix + "password"]
    return ip, user, pwd


def load_hexapod_ip():
    """
    Try to read the hexapod controller IP from ~/access.json
    (key: hexapod_ip_address). Returns None if not found.
    """
    try:
        with open(CREDENTIALS_FILE_NAME, "r") as f:
            cfg = json.load(f)
        return cfg.get("hexapod_ip_address")
    except Exception:
        return None


class NetBooterHTTP:
    def __init__(self, ip, username, password, timeout=10):
        self.ip = ip
        self.auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.conn = http.client.HTTPConnection(ip, timeout=timeout)

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def _req(self, method, path, body=b"", headers=None):
        headers = {} if headers is None else dict(headers)
        headers["Authorization"] = f"Basic {self.auth}"
        headers.setdefault("Content-Length", str(len(body)))

        self.conn.putrequest(method, path)
        for k, v in headers.items():
            self.conn.putheader(k, v)
        self.conn.endheaders()
        if body:
            self.conn.send(body)

        resp = self.conn.getresponse()
        data = resp.read().decode(errors="ignore")
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} {method} {path}: {data[:200]!r}")
        return data

    def status(self, outlet: int) -> bool:
        if outlet not in (1, 2, 3, 4, 5):
            raise ValueError("outlet must be 1..5")

        xml = self._req("GET", "/status.xml")
        idx = outlet - 1
        m = re.search(rf"<rly{idx}>([01])</rly{idx}>", xml)
        if not m:
            raise RuntimeError(f"Could not parse /status.xml for outlet {outlet}:\n{xml}")
        return m.group(1) == "1"

    def _toggle_press(self, outlet: int):
        idx = outlet - 1
        self._req(
            "POST",
            f"/cmd.cgi?rly={idx}",
            body=b"1",
            headers={"Content-Type": "text/plain"},
        )

    def ensure(self, outlet: int, want_on: bool, verify_delay=0.25) -> bool:
        cur = self.status(outlet)
        if cur == want_on:
            return True
        self._toggle_press(outlet)
        time.sleep(verify_delay)
        return self.status(outlet) == want_on

    def on(self, outlet: int) -> bool:
        return self.ensure(outlet, True)

    def off(self, outlet: int) -> bool:
        return self.ensure(outlet, False)


def run_cmd(cmd: str):
    # Run locally; scripts themselves handle any ssh they need
    return subprocess.run(cmd, shell=True, check=True)

def ioc_stop():
    return run_cmd(IOC_STOP_SCRIPT)

def ioc_start():
    return run_cmd(IOC_START_SCRIPT)

def caget(pv: str) -> str:
    return subprocess.check_output(["caget", "-t", pv], text=True).strip()


def caput(pv: str, value):
    subprocess.check_call(["caput", pv, str(value)])


def tcp_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def wait_for_controller(host: str, port: int, timeout_s: int = 120, poll_s: int = 5) -> bool:
    """
    Wait until the hexapod controller is accepting TCP connections.
    This confirms the controller firmware has fully booted.
    """
    deadline = time.time() + timeout_s
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        if tcp_port_open(host, port):
            print(f"  Hexapod controller {host}:{port} is responding (attempt {attempt}).")
            return True
        remaining = int(deadline - time.time())
        print(f"  Hexapod controller {host}:{port} not yet ready "
              f"(attempt {attempt}, {remaining}s remaining)...")
        time.sleep(poll_s)
    return False


def wait_for_pv_connected(pv: str, timeout_s=120, poll_s=3) -> str:
    """
    Wait until a PV is reachable via caget.
    Returns the PV value once connected.
    Raises RuntimeError if the PV is not reachable within timeout.
    """
    deadline = time.time() + timeout_s
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            val = caget(pv)
            print(f"  PV {pv} is connected (value={val})")
            return val
        except Exception:
            remaining = int(deadline - time.time())
            print(f"  Waiting for IOC... {pv} not yet available "
                  f"(attempt {attempt}, {remaining}s remaining)")
            time.sleep(poll_s)
    raise RuntimeError(
        f"PV {pv} did not become reachable within {timeout_s}s — IOC may have failed to start"
    )


def wait_for_all_enabled(timeout_s=180, poll_s=1) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if caget(PV_ALL_ENABLED) == "1":
                return True
        except Exception:
            pass
        time.sleep(poll_s)
    return False


def main():
    ap = argparse.ArgumentParser(
        description=f"Hexapod reboot: stop IOC, power-cycle outlet {HEXAPOD_OUTLET}, start IOC, verify EPICS enabled"
    )
    ap.add_argument(
        "--pdu",
        default="a",
        choices=["a", "b", "A", "B"],
        help="Select PDU creds from ~/access.json (default: a)",
    )
    ap.add_argument("--off-wait", type=int, default=10,
                    help="Seconds to wait after power OFF (default: 10)")
    ap.add_argument("--on-wait", type=int, default=30,
                    help="Seconds to wait after power ON before checking controller (default: 30)")
    ap.add_argument("--hexapod-ip", type=str, default=None,
                    help="Hexapod controller IP for readiness check "
                         "(default: read hexapod_ip_address from ~/access.json)")
    ap.add_argument("--hexapod-port", type=int, default=5001,
                    help="Hexapod controller TCP port for readiness check (default: 5001)")
    ap.add_argument("--controller-timeout", type=int, default=120,
                    help="Seconds to wait for hexapod controller to become reachable (default: 120)")
    ap.add_argument("--ioc-settle", type=int, default=10,
                    help="Seconds to wait after IOC start before checking PVs (default: 10)")
    ap.add_argument("--ioc-timeout", type=int, default=120,
                    help="Seconds to wait for IOC PVs to become available (default: 120)")
    ap.add_argument("--enable-timeout", type=int, default=180,
                    help="Seconds to wait for HexapodAllEnabled=1 (default: 180)")
    args = ap.parse_args()

    # Resolve hexapod controller IP
    hexapod_ip = args.hexapod_ip or load_hexapod_ip()

    ip, user, pwd = load_pdu_creds(args.pdu)
    pdu = NetBooterHTTP(ip, user, pwd)

    try:
        # ----- 1. Stop the EPICS IOC -----
        print("=" * 60)
        print("Step 1: Stopping hexapod IOC...")
        print("=" * 60)
        ioc_stop()

        # ----- 2. Power OFF the hexapod controller, wait -----
        print()
        print("=" * 60)
        print(f"Step 2: Powering OFF hexapod controller (outlet {HEXAPOD_OUTLET})...")
        print("=" * 60)
        if not pdu.off(HEXAPOD_OUTLET):
            raise RuntimeError("PDU power OFF failed (state did not become OFF)")

        print(f"Waiting {args.off_wait}s for power to fully discharge...")
        time.sleep(args.off_wait)

        # ----- 3. Power ON the hexapod controller, wait -----
        print()
        print("=" * 60)
        print(f"Step 3: Powering ON hexapod controller (outlet {HEXAPOD_OUTLET})...")
        print("=" * 60)
        if not pdu.on(HEXAPOD_OUTLET):
            raise RuntimeError("PDU power ON failed (state did not become ON)")

        print(f"Waiting {args.on_wait}s for controller hardware to initialize...")
        time.sleep(args.on_wait)

        # ----- 3b. Verify the controller is actually ready -----
        if hexapod_ip:
            print()
            print("=" * 60)
            print(f"Step 3b: Verifying hexapod controller is ready "
                  f"({hexapod_ip}:{args.hexapod_port})...")
            print("=" * 60)
            if not wait_for_controller(hexapod_ip, args.hexapod_port,
                                       timeout_s=args.controller_timeout, poll_s=5):
                raise RuntimeError(
                    f"Hexapod controller {hexapod_ip}:{args.hexapod_port} did not become "
                    f"reachable within {args.controller_timeout}s after power-on"
                )
            # Extra settle time after TCP port opens — firmware may still be initializing
            print("Controller TCP port is open. Waiting 5s extra for firmware settle...")
            time.sleep(5)
        else:
            print()
            print("(No hexapod controller IP configured — skipping readiness check.)")
            print("(Set hexapod_ip_address in ~/access.json or use --hexapod-ip to enable.)")

        # ----- 4. Restart the EPICS IOC -----
        print()
        print("=" * 60)
        print("Step 4: Starting hexapod IOC (via hexapod_IOC.sh)...")
        print("=" * 60)
        ioc_start()

        # ----- 5. Let the IOC settle before checking PVs -----
        print(f"Waiting {args.ioc_settle}s for IOC to settle...")
        time.sleep(args.ioc_settle)

        # ----- 6. Wait for IOC PVs to become available -----
        print()
        print("=" * 60)
        print(f"Step 5: Waiting for IOC PVs to become available "
              f"(timeout {args.ioc_timeout}s)...")
        print("=" * 60)
        val = wait_for_pv_connected(PV_ALL_ENABLED, timeout_s=args.ioc_timeout, poll_s=3)

        # ----- 7. Verify / enable the hexapod driver -----
        print()
        print("=" * 60)
        print("Step 6: Verifying hexapod driver enable status...")
        print("=" * 60)

        if val == "1":
            print("OK: Hexapod is already enabled (HexapodAllEnabled=1).")
            return 0

        # Not yet enabled — wait 3 s and check again
        print(f"{PV_ALL_ENABLED}={val} (disabled); rechecking in 3 s...")
        time.sleep(3)

        try:
            val = caget(PV_ALL_ENABLED)
        except Exception:
            val = "0"

        if val == "1":
            print("OK: Hexapod is enabled (HexapodAllEnabled=1).")
            return 0

        # Still disabled — issue the enable command
        print(f"{PV_ALL_ENABLED}={val} (still disabled); issuing {PV_ENABLE_WORK}=1 ...")
        caput(PV_ENABLE_WORK, 1)

        # Poll every 1 s to confirm it becomes enabled
        print(f"Polling {PV_ALL_ENABLED} every 1 s (timeout {args.enable_timeout}s)...")
        if not wait_for_all_enabled(timeout_s=args.enable_timeout, poll_s=1):
            raise RuntimeError(
                f"{PV_ALL_ENABLED} did not become 1 within {args.enable_timeout}s"
            )

        print("OK: Hexapod is enabled (HexapodAllEnabled=1).")
        return 0

    finally:
        pdu.close()


if __name__ == "__main__":
    raise SystemExit(main())
