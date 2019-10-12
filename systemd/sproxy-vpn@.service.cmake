[Unit]
Description=sproxy vpndemo with config %I.conf
After=network.target

[Service]
Type=forking
WorkingDirectory=-/var/lib/sproxy
Environment=LD_LIBRARY_PATH=@CMAKE_INSTALL_PREFIX@/lib
ExecStart=@CMAKE_INSTALL_PREFIX@/sbin/vpndemo -D -c /etc/sproxy/%I.conf
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=SIGKILL

[Install]
WantedBy=multi-user.target
