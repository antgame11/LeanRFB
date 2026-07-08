#!/bin/bash
xvfb-run --server-args="-screen 0 1024x768x24" bash -c 'stdbuf -oL -eL ./vncviewer > vncviewer_debug.log 2>&1 & VIEWER_PID=$!; sleep 2; xdotool key --delay 100 Return; sleep 5; kill $VIEWER_PID; wait $VIEWER_PID 2>/dev/null'
echo "Done"
