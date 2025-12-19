[Unit]
Description=sproxy http socket

[Socket]
Backlog=10000
DeferAcceptSec=60s
ReusePort=yes
FileDescriptorName=http
ListenStream=[::]:80
Service=sproxy.service

[Install]
WantedBy=sockets.target
