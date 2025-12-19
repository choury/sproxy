[Unit]
Description=sproxy ssl socket

[Socket]
Backlog=10000
DeferAcceptSec=60s
ReusePort=yes
FileDescriptorName=ssl
ListenStream=[::]:443
Service=sproxy.service

[Install]
WantedBy=sockets.target
