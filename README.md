sproxy ![Build Status](https://github.com/choury/sproxy/actions/workflows/build.yml/badge.svg?branch=master)
======
+ Support Linux and macOS
+ http proxy
+ http/http2 proxy over ssl

build
=====
  require: openssl 1.1.1 and c++14
 
  build: cmake . && make

TODO
======
- [ ] 支持动态生成pac文件
- [x] 写一个客户端，用来做些运维操作
- [ ] 支持quic协议(doing)
