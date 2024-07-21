[Unit]
Description=sproxy vpndemo
After=network.target

[Service]
Type=simple
LimitCORE=infinity
WorkingDirectory=-/var/lib/sproxy
Environment=LD_LIBRARY_PATH=@CMAKE_INSTALL_PREFIX@/lib
ExecStart=@CMAKE_INSTALL_PREFIX@/sbin/vpndemo -c /etc/sproxy/sproxy.conf
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
