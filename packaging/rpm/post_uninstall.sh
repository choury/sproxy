#!/bin/sh

if [ "$1" -eq 0 ]; then
    # Package removal
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
    fi
elif [ "$1" -ge 1 ]; then
    # Upgrade
    if command -v systemctl >/dev/null; then
        systemctl try-restart sproxy.service
    fi
fi
