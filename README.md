sproxy [![Build Status](https://travis-ci.org/choury/sproxy.svg?branch=master)](https://travis-ci.org/choury/sproxy)
======
+ Linux Only!!
+ http proxy over ssl and dtls

build
=====
  require: openssl 1.0.2
  
  build: cmake . && make

TODO
======
- [x] 动态job机制，减少cpu使用率
- [ ] Guest_sni 可以转化为 Guest_s(2)
