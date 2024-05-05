//
// Created by 周威 on 2022/4/24.
//

#ifndef SPROXY_BUFFER_H
#define SPROXY_BUFFER_H

#include "common/common.h"

#include <list>
#include <set>
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
    std::unique_ptr<void, void(*)(void*)> base;
    off_t off;
public:
    Block(const Block&) = delete;
    Block& operator=(const Block&) = delete;

    explicit Block(size_t size, off_t prior = PRIOR_HEAD):
        base(malloc(size + prior), free), off(prior){
    }
    explicit Block(const void* ptr, size_t size, off_t prior = PRIOR_HEAD):
        base(malloc(size + prior), free), off(prior)
    {
        if(size == 0){
            return;
        }
        memcpy((char*)base.get() + off, ptr, size);
    }
    Block(Block&& p) noexcept : base(std::move(p.base)){
        off = p.off;
        p.off = 0;
    };

    [[nodiscard]] off_t tell() const{
        return off;
    }

    void* reserve(int len){
        assert( off >= -len);
        off += len;
        return (char*)base.get() + off;
    }
    [[nodiscard]] void* data() const{
        return (char*)base.get() + off;
    }
    friend class Buffer;
};

//封装了Block，但是多了长度和id信息
//并且可以管理const 类型的buffer，只有当遇到下面几种情况时才会复制buffer
//reserve的参数为负数，truncate 需要扩展空间，调用mutable_data() 或者end()
//因此每次调用返回的指针地址不可cache
class Buffer{
    std::shared_ptr<void> ptr = nullptr;
    off_t off = 0;
public:
    uint64_t id = 0;
    size_t len = 0;
    size_t cap = 0;
    explicit Buffer(size_t cap, uint64_t id = 0);
    Buffer(const void* data, size_t len, uint64_t id = 0);
    Buffer(Block&& data, size_t len, uint64_t id = 0);
    Buffer(std::nullptr_t, uint64_t id = 0);
    Buffer(Buffer&& b) noexcept;
    Buffer(const Buffer&) noexcept = default;
    // 增加/减少预留空间 off 为正增加，为负减少
    void reserve(int p);
    // 从末尾截断/扩展数据, 返回截断前的长度
    size_t truncate(size_t left);
    [[nodiscard]] const void* data() const;
    void* mutable_data();
    size_t refs();
};


#ifndef insert_iterator
#ifdef HAVE_CONST_ITERATOR_BUG
#define insert_iterator iterator
#else
#define insert_iterator const_iterator
#endif
#endif



#if 0
using buff_iterator = std::list<Buffer>::insert_iterator;
class WBuffer {
    std::list<Buffer> write_queue;
    size_t  len = 0;
public:
    ~WBuffer();
    [[nodiscard]] size_t length() const;
    buff_iterator start();
    buff_iterator end();
    buff_iterator push(buff_iterator i, Buffer&& bb);
    ssize_t Write(const std::function<ssize_t(std::list<Buffer>&)>& write_func, std::set<uint64_t>& writed_list);
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
#endif

//CBuffer 是一个环形buffer
class CBuffer {
    char content[BUF_LEN*2];
    uint64_t offset = 0;
    size_t len = 0;
public:
    //for put
    char* end(); 
    //left返回的是可以在end() 返回的指针后面可以直接写入的数据长度
    size_t left();
    void append(size_t l);
    //put类似与先调用end()获取指针写数据后，再调用append调整长度
    ssize_t put(const void* data, size_t size);
    [[nodiscard]] uint64_t Offset() const{
        return offset;
    };

    //for get
    [[nodiscard]] size_t length() const;
    [[nodiscard]] size_t cap() const;
    Buffer get();
    void consume(size_t l);
};

//EBuffer也是一个环形buffer,只不过数据快写满的话，它会动态扩容
class EBuffer {
    char* content;
    size_t size = BUF_LEN * 2;
    uint64_t offset = 0;
    size_t len = 0;
    void expand(size_t newsize);
    static uint64_t put(void* dst, uint64_t pos, size_t size, const void* data, size_t dsize);
public:
    EBuffer() {
        content = new char[size];
    }
    EBuffer(EBuffer&& copy) noexcept :
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
    [[nodiscard]] size_t left() const;
    char* end();
    void append(size_t l);
    ssize_t put(const void* data, size_t size);
    [[nodiscard]] uint64_t Offset() const{
        return offset;
    };

    //for get
    [[nodiscard]] size_t length() const;
    [[nodiscard]] size_t cap() const;
    Buffer get();
    void consume(size_t l);
};


#endif //SPROXY_BUFFER_H
