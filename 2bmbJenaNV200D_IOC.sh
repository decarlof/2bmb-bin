#!/bin/bash

# Define variables
TAB_NAME="2bmbJena IOC"
REMOTE_USER="2bmb"
REMOTE_HOST="arcturus"
WORK_DIR="/net/s2dserv/xorApps/epics/synApps_6_3/ioc/JenaNV200D/iocBoot/iocJenaNV200D/"

# Open a new tab in gnome-terminal, SSH into tomdet, activate conda, and run Python (without login shell)
gnome-terminal --tab --title="$TAB_NAME" -- bash -c "
    ssh -t ${REMOTE_USER}@${REMOTE_HOST} '
        cd ${WORK_DIR}
        ../../bin/rhel9-x86_64/JenaNV200D st.cmd.Linux

    ';
"