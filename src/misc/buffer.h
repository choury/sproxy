//
// Created by 周威 on 2022/4/24.
//

#ifndef SPROXY_BUFFER_H
#define SPROXY_BUFFER_H

#include "common/common.h"

#include <list>
#include <functional>
#include <memory>

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#define PRIOR_HEAD 80

/*
 * 这个类维护一个缓冲区，但是申请的时候会多申请一个固定长度的头部（作为预留部分）
 * 可以通过reserve操作来移动当前数据的位置，如果参数为正，则向后移动（增加预留），如果为负，则向前移动
 */
class Block{
    void* base;
    off_t off;
public:
    explicit Block(size_t size, off_t prior = PRIOR_HEAD):
        base(malloc(size + prior)), off (prior){
    }
    explicit Block(const void* ptr, size_t size, off_t prior = PRIOR_HEAD):
        base(malloc(size + prior)), off(prior)
    {
        if(size == 0){
            return;
        }
        memcpy((char*)base+off, ptr, size);
    }
    Block(Block&& p){
        base = p.base;
        off = p.off;
        p.base = nullptr;
    };

    Block(const Block&) = delete;
    void* reserve(int len){
        assert( off >= -len);
        off += len;
        return (char*)base + off;
    }
    void* data() const{
        return (char*)base + off;
    }
    ~Block(){
        free(base);
    }
};

//本质上是Block的封装，但是多了长度和id信息
//至于为啥有的时候需要直接使用Block类，因为Block类构造的时候指定的长度并不一定是需要的长度
class Buffer{
    std::shared_ptr<Block> ptr;
public:
    uint64_t id = 0;
    size_t len = 0;
    size_t cap = 0;
    Buffer(const Buffer&) = delete;
    Buffer(size_t len, uint64_t id = 0);
    Buffer(const void* ptr, size_t len, uint64_t id = 0);
    Buffer(std::shared_ptr<Block> ptr, size_t len, uint64_t id = 0);
    Buffer(std::nullptr_t, uint64_t id = 0);
    Buffer(Buffer&& b);
    // 增加/减少预留空间 off 为正增加，为负减少
    void* reserve(int off);
    // 从末尾截断/扩展数据, 返回截断前的长度
    size_t truncate(size_t left);
    void* data() const;
    void* end() const;
};


#ifndef insert_iterator
#ifdef HAVE_CONST_ITERATOR_BUG
#define insert_iterator iterator
#else
#define insert_iterator const_iterator
#endif
#endif


using buff_iterator = std::list<Buffer>::insert_iterator;
class WBuffer {
    std::list<Buffer> write_queue;
    size_t  len = 0;
public:
    ~WBuffer();
    size_t length();
    buff_iterator start();
    buff_iterator end();
    buff_iterator push(buff_iterator i, Buffer&& bb);
    ssize_t  Write(std::function<ssize_t(const void*, size_t, uint64_t)> write_func);
};


class RBuffer {
    char content[BUF_LEN*2];
    size_t len = 0;
public:
    //for put
    size_t left();
    char* end();
    size_t add(size_t l);
    ssize_t put(const void* data, size_t size);

    //for get
    size_t length();
    size_t cap();
    const char* data();
    size_t consume(size_t l);
};

class CBuffer {
    char content[BUF_LEN*2];
    uint64_t offset = 0;
    size_t len = 0;
public:
    //for put
    size_t left();
    char* end();
    void add(size_t l);
    ssize_t put(const void* data, size_t size);
    uint64_t Offset(){
        return offset;
    };

    //for get
    size_t length();
    size_t cap();
    size_t get(char* buff, size_t len);
    void consume(size_t l);
};


#define MAX_BUF_LEN (1024*1024)
class EBuffer {
    char* content;
    size_t size = BUF_LEN * 2;
    uint64_t offset = 0;
    size_t len = 0;
    void expand(size_t newsize);
public:
    EBuffer() {
        content = new char[size];
    }
    EBuffer(EBuffer&& copy):
            content(copy.content),
            size(copy.size),
            offset(copy.offset),
            len(copy.len)
    {
        content = copy.content;
        copy.content = nullptr;
        copy.size = 0;
        copy.len = 0;
    }
    ~EBuffer(){
        delete []content;
    }
    //for put
    size_t left();
    char* end();
    void add(size_t l);
    ssize_t put(const void* data, size_t size);
    uint64_t Offset(){
        return offset;
    };

    //for get
    size_t length();
    size_t cap();
    size_t get(char* buff, size_t len);
    void consume(size_t l);
};


#endif //SPROXY_BUFFER_H
