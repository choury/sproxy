[Unit]
Description=sproxy quic socket

[Socket]
ReusePort=yes
FileDescriptorName=quic
ListenDatagram=[::]:443
Service=sproxy.service

[Install]
WantedBy=sockets.target
