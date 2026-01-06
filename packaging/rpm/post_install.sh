#!/bin/sh

if [ "$1" -eq 1 ]; then
    # Initial installation
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
    fi
elif [ "$1" -eq 2 ]; then
    # Upgrade
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
        systemctl try-restart sproxy.service
    fi
fi
