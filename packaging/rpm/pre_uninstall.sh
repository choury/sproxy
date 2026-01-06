#!/bin/sh

if [ "$1" -eq 0 ]; then
    # Package removal, not upgrade
    if command -v systemctl >/dev/null; then
        systemctl stop sproxy.service || true
        systemctl disable sproxy.service || true
        
        for socket in sproxy-http.socket sproxy-ssl.socket sproxy-quic.socket; do
            if systemctl list-unit-files "$socket" >/dev/null 2>&1; then
                systemctl stop "$socket" || true
            fi
        done
    fi
fi