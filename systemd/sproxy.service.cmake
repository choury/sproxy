[Unit]
Description=sproxy for linux
After=network.target

[Service]
Type=forking
WorkingDirectory=-@CMAKE_INSTALL_PREFIX@/etc/sproxy
ExecStart=@CMAKE_INSTALL_PREFIX@/bin/sproxy -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
Alias=sproxy.service
