sproxy [![Build Status](https://api.travis-ci.com/choury/sproxy.svg?branch=master)](https://travis-ci.com/choury/sproxy)
======
+ Support Linux and macOS
+ http proxy
+ http/http2 proxy over ssl

build
=====
  require: openssl 1.0.2
  
  build: cmake . && make

TODO
======
- [ ] 支持动态生成pac文件
- [x] 写一个客户端，用来做些运维操作
- [ ] 支持quic协议(doing)