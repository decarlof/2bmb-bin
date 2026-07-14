#!/bin/bash

# Define variables
TAB_NAME="2bmBLEPS IOC"
REMOTE_USER="2bmb"
REMOTE_HOST="arcturus"
APP_NAME="2bmBLEPS"

# Open a new tab in gnome-terminal, SSH into arcturus, kill the IOC
gnome-terminal --tab --title="$TAB_NAME" -- bash -c "
    ssh -t ${REMOTE_USER}@${REMOTE_HOST} '
        kill_IOC.sh ${APP_NAME}
    ';
"
