#!/bin/bash

# Define variables
TAB_NAME="2bmBLEPS IOC"
REMOTE_USER="2bmb"
REMOTE_HOST="arcturus"
WORK_DIR="/net/s2dserv/xorApps/epics/synApps_6_3/ioc/2bmBLEPS/iocBoot/ioc2bmBLEPS/softioc/"

# Open a new tab in gnome-terminal, SSH into arcturus, run the softIoc launcher
gnome-terminal --tab --title="$TAB_NAME" -- bash -c "
    ssh -t ${REMOTE_USER}@${REMOTE_HOST} '
        cd ${WORK_DIR}
        ./2bmBLEPS.pl run
    ';
"
