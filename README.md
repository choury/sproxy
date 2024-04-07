sproxy ![Build Status](https://github.com/choury/sproxy/actions/workflows/build.yml/badge.svg?branch=master)
======
+ Support Linux and macOS
+ http proxy
+ http/http2 proxy over ssl

build
=====
  require: openssl 1.1.1, json-c and c++17
 
  build: cmake . && make

TODO
======
- [ ] 支持动态生成pac文件
- [x] 支持quic协议
- [x] 支持http3的sni功能
- [ ] 支持quic bbr 拥塞算法
