//
// Created by choury on 2022/4/24.
//

#ifndef SPROXY_BUFFER_H
#define SPROXY_BUFFER_H

#include "common/common.h"
#include "hook/reflect.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <atomic>
#include <sys/types.h>

#include <string>
#include <memory>
#include <vector>
#include <deque>
#include <set>

#define PRIOR_HEAD 128

//数据块统一布局: [RefHead][PRIOR_HEAD预留][数据]
//引用计数内嵌在分配头部，Buffer拷贝只做原子加减，不再额外分配shared_ptr控制块
struct RefHead{
    std::atomic<uint32_t> refs;
    uint64_t pad; //凑满16字节，保证数据区16字节对齐
};
static_assert(sizeof(RefHead) == 16, "RefHead must keep data 16-byte aligned");

//返回数据区基址(预留区起点)，失败返回nullptr，引用计数初始化为1
inline void* buf_alloc(size_t memcap){
    char* raw = (char*)malloc(sizeof(RefHead) + memcap);
    if(raw == nullptr){
        return nullptr;
    }
    ((RefHead*)raw)->refs.store(1, std::memory_order_relaxed);
    return raw + sizeof(RefHead);
}

inline void buf_free(void* mem){
    if(mem){
        free((char*)mem - sizeof(RefHead));
    }
}

inline RefHead* buf_refhead(void* mem){
    return (RefHead*)((char*)mem - sizeof(RefHead));
}

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
        base(buf_alloc(size + prior), buf_free), off(prior){
    }
    explicit Block(const void* ptr, size_t size, off_t prior = PRIOR_HEAD):
        base(buf_alloc(size + prior), buf_free), off(prior)
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
    void reflect(IVisitor& v) {
        reflect_all(off);
    }
};

//封装了Block，但是多了长度和id信息
//并且可以管理const 类型的buffer，只有当遇到下面几种情况时才会复制buffer
//reserve的参数为负数，truncate 需要扩展空间，调用mutable_data()
//因此每次调用返回的指针地址不可cache
class Buffer{
    void* mem = nullptr; //数据区基址(含预留区)，其前16字节为RefHead引用计数
    off_t off = 0;

    void addref(){
        buf_refhead(mem)->refs.fetch_add(1, std::memory_order_relaxed);
    }
    void release(){
        if(mem && buf_refhead(mem)->refs.fetch_sub(1, std::memory_order_release) == 1){
            std::atomic_thread_fence(std::memory_order_acquire);
            buf_free(mem);
        }
        mem = nullptr;
    }
public:
    uint64_t id = 0;
    size_t len = 0;
    size_t cap = 0;
    explicit Buffer(size_t cap, uint64_t id = 0);
    Buffer(const void* data, size_t len, uint64_t id = 0);
    Buffer(Block&& data, size_t len, uint64_t id = 0);
    Buffer(std::nullptr_t, uint64_t id = 0);
    Buffer(Buffer&& b) noexcept;
    Buffer(const Buffer& b) noexcept;
    Buffer& operator=(Buffer&& b) noexcept;
    ~Buffer();
    // 增加/减少预留空间 off 为正增加，为负减少
    void reserve(int p);
    // 从末尾截断/扩展数据, 返回截断前的长度
    size_t truncate(size_t left);
    [[nodiscard]] const void* data() const;
    void* mutable_data();
    size_t refs() const;
    // 末尾剩余可写空间(独占时)，共享或无数据时为0，不触发COW
    [[nodiscard]] size_t room() const;
    void reflect(IVisitor& v) {
        reflect_named("data", std::span<const std::byte>((const std::byte*)data(), len));
        reflect_all(id, len, cap);
    }
};


class CBuffer {
    std::deque<Buffer> buffers;
    size_t total_len = 0;
public:
    ssize_t put(Buffer&& bb);
    // 返回队尾Buffer末尾的可写空间(供直接读入数据，不触发COW)
    // 队列为空、队尾id不匹配或队尾被共享时返回空span
    std::span<char> tailRoom(uint64_t id);
    // 向tailRoom返回的空间写入了l字节后，推进队尾
    void tailPush(size_t l);

    //for get
    [[nodiscard]] size_t length() const;
    [[nodiscard]] size_t cap() const;
    [[nodiscard]] bool empty() const;
    //真实已分配字节数(各Buffer的cap之和,不含deque节点开销)
    [[nodiscard]] size_t mem_usage() const;
    Buffer get();
    const std::deque<Buffer>& data() const;
    std::set<uint64_t> consume(size_t l);
    void reflect(IVisitor& v) {
        reflect_all(total_len, buffers);
    }
};

struct DataRange {
    size_t start;
    size_t end;
    DataRange(size_t s, size_t e) : start(s), end(e) {}
    void reflect(IVisitor& v) {
        reflect_all(start, end);
    }
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
    void reflect(IVisitor& v) {
        reflect_named("data", std::span<const std::byte>((const std::byte*)content, capacity));
        reflect_all(capacity, ranges);
    }
};

std::string dumpDest(const Destination& addr);

#endif //SPROXY_BUFFER_H
