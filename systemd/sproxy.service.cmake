[Unit]
Description=sproxy for linux
After=network.target

[Service]
Type=simple
LimitCORE=infinity
WorkingDirectory=-/var/lib/sproxy
ExecStart=@CMAKE_INSTALL_PREFIX@/bin/sproxy -c /etc/sproxy/sproxy.conf
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
