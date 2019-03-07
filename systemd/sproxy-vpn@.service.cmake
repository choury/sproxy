[Unit]
Description=sproxy vpndemo on %I
After=network.target

[Service]
Type=forking
WorkingDirectory=-@CMAKE_INSTALL_PREFIX@/etc/sproxy
Environment=LD_LIBRARY_PATH=@CMAKE_INSTALL_PREFIX@/lib
ExecStart=@CMAKE_INSTALL_PREFIX@/sbin/vpndemo %I http://172.16.35.1:3333
ExecReload=/bin/kill -USR2 $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
Alias=sproxy-vpn.service
