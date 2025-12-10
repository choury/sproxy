//
// Created by choury on 2022/4/24.
//

#ifndef SPROXY_BUFFER_H
#define SPROXY_BUFFER_H

#include "common/common.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>

#include <string>
#include <memory>
#include <vector>
#include <deque>
#include <set>

#define PRIOR_HEAD 128

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
//reserve的参数为负数，truncate 需要扩展空间，调用mutable_data()
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
    Buffer& operator=(Buffer&&) noexcept;
    // 增加/减少预留空间 off 为正增加，为负减少
    void reserve(int p);
    // 从末尾截断/扩展数据, 返回截断前的长度
    size_t truncate(size_t left);
    [[nodiscard]] const void* data() const;
    void* mutable_data();
    size_t refs();
};


class CBuffer {
    std::deque<Buffer> buffers;
    size_t total_len = 0;
public:
    ssize_t put(Buffer&& bb);

    //for get
    [[nodiscard]] size_t length() const;
    [[nodiscard]] size_t cap() const;
    [[nodiscard]] bool empty() const;
    Buffer get();
    const std::deque<Buffer>& data() const;
    std::set<uint64_t> consume(size_t l);
};

struct DataRange {
    size_t start;
    size_t end;
    DataRange(size_t s, size_t e) : start(s), end(e) {}
};

//EBuffer是一个环形buffer,只不过数据快写满的话，它会动态扩容
//现在支持不连续数据存储，可以在任意位置插入数据并自动合并相邻范围
class EBuffer {
    char* content;
    size_t capacity;
    std::vector<DataRange> ranges; // 记录有数据的范围
    void expand(size_t newsize);
    static size_t put(void* dst, size_t pos, size_t size, const void* data, size_t dsize);
    void merge_ranges(size_t start, size_t end);
public:
    EBuffer(size_t size = BUF_LEN * 2): capacity(size) {
        content = new char[capacity];
        ranges.emplace_back(DataRange{0, 0});
    }
    EBuffer(EBuffer&& copy) noexcept :
            content(copy.content),
            capacity(copy.capacity)
    {
        content = copy.content;
        copy.content = nullptr;
        copy.capacity = 0;
        ranges = std::move(copy.ranges);
    }
    ~EBuffer(){
        delete []content;
    }
    //for put
    [[nodiscard]] size_t left() const;
    char* end();
    void append(size_t l);
    ssize_t put(const void* data, size_t size);
    ssize_t put_at(size_t pos, const void* data, size_t size);
    [[nodiscard]] size_t Offset() const{
        return ranges[0].start;
    };

    //for get
    [[nodiscard]] size_t length() const;
    [[nodiscard]] size_t cap() const;
    Buffer get(size_t len = MAX_BUF_LEN);
    Buffer get_at(size_t pos, size_t len);
    void consume(size_t l);

    // 不连续数据相关函数
    [[nodiscard]] const std::vector<DataRange>& get_ranges() const;
    [[nodiscard]] size_t continuous_length() const;
    [[nodiscard]] size_t continuous_length_at(size_t pos) const;
};

std::string dumpDest(const Destination& addr);

#endif //SPROXY_BUFFER_H
