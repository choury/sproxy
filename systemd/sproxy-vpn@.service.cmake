[Unit]
Description=sproxy vpndemo on %I
After=network.target

[Service]
Type=forking
WorkingDirectory=-@CMAKE_INSTALL_PREFIX@/etc/sproxy
Environment=LD_LIBRARY_PATH=@CMAKE_INSTALL_PREFIX@/lib
ExecStart=@CMAKE_INSTALL_PREFIX@/sbin/vpndemo -D -I %I
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
Alias=sproxy-vpn.service
