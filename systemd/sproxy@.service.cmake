[Unit]
Description=sproxy for linux witch config %I.conf
After=network.target

[Service]
Type=forking
WorkingDirectory=-/var/lib/sproxy
ExecStart=@CMAKE_INSTALL_PREFIX@/bin/sproxy -c /etc/sproxy/%I.conf -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
