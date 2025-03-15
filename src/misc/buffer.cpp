//
// Created by 周威 on 2022/4/26.
//
#include "buffer.h"
#include "common/common.h"


Buffer::Buffer(size_t cap, uint64_t id):
        ptr(malloc(cap + PRIOR_HEAD), free), off(PRIOR_HEAD), id(id), cap(cap + PRIOR_HEAD)
{
    assert(this->ptr != nullptr);
}


Buffer::Buffer(const void* data, size_t len, uint64_t id):
        ptr(malloc(len + PRIOR_HEAD), free), off(PRIOR_HEAD), id(id), len(len), cap(len + PRIOR_HEAD)
{
    memcpy((char*)ptr.get() + PRIOR_HEAD, data, len);
}

Buffer::Buffer(Block&& data, size_t len, uint64_t id):
        ptr(data.base.release(), free), off(data.off), id(id), len(len), cap(len + data.off)
{
    assert(this->ptr != nullptr);
}

Buffer::Buffer(std::nullptr_t, uint64_t id): id(id){
}

Buffer::Buffer(Buffer&& b) noexcept{
    assert(b.ptr != nullptr || b.len == 0);
    id = b.id;
    len = b.len;
    cap = b.cap;
    off = b.off;
    if(b.ptr){
        ptr = std::move(b.ptr);
    }
    b.ptr = nullptr;
    b.cap = 0;
    b.len = 0;
    b.off = 0;
}

Buffer& Buffer::operator=(Buffer&& b) noexcept{
    assert(b.ptr != nullptr || b.len == 0);
    id = b.id;
    len = b.len;
    cap = b.cap;
    off = b.off;
    if(b.ptr){
        ptr = std::move(b.ptr);
    }
    b.ptr = nullptr;
    b.cap = 0;
    b.len = 0;
    b.off = 0;
    return *this;
}

void Buffer::reserve(int p){
    if(p == 0) {
        return;
    }
    assert((int)len - p >= 0);
    len -= p;
    if(ptr == nullptr) {
        assert(cap == 0);
        cap = len + PRIOR_HEAD;
        ptr = std::shared_ptr<void>(malloc(cap), free);
        off = PRIOR_HEAD;
        return;
    }
    assert( off + p >= 0);
    off += p;
}

size_t Buffer::truncate(size_t left) {
    size_t origin = len;
    if(ptr) {
        if(off + left <= cap) {
            len = left;
            return origin;
        }
        cap = left + off;
        auto new_ptr = std::shared_ptr<void>(malloc(cap), free);
        memcpy((char*)new_ptr.get() + off, (char*)ptr.get() + off, len);
        ptr = new_ptr;
    } else {
        assert(len == 0 && cap == 0);
        cap = left + PRIOR_HEAD;
        ptr = std::shared_ptr<void>(malloc(cap), free);
        off = PRIOR_HEAD;
    }
    len = left;
    return origin;
}

const void* Buffer::data() const{
    if(ptr == nullptr) {
        assert(len == 0 && cap == 0);
        return nullptr;
    }
    return (char*)ptr.get() + off;
}

void* Buffer::mutable_data() {
    if(ptr == nullptr) {
        assert(len == 0 && cap == 0 && off == 0);
        return nullptr;
    }else if(ptr.use_count() > 1) {
        cap = len + off;
        auto new_ptr = std::shared_ptr<void>(malloc(cap), free);
        memcpy((char*)new_ptr.get() + off, (char*)ptr.get() + off, len);
        LOGD(DRWER, "split buffer: %p -> %p: %zd\n", ptr.get(), new_ptr.get(), len);
        ptr = new_ptr;
    }
    return (char*)ptr.get() + off;
}

size_t Buffer::refs() {
    if(ptr) {
        return ptr.use_count();
    }
    return 0;
}

size_t CBuffer::left(){
    uint32_t start = offset % sizeof(content);
    uint32_t finish = (offset + len) % sizeof(content);
    if(finish > start || len == 0){
        return sizeof(content) - finish;
    }
    return start - finish;
}

size_t CBuffer::length() const{
    assert(len <= sizeof(content));
    return len;
}

size_t CBuffer::cap() const{
    return sizeof(content) - len;
}

void CBuffer::append(size_t l){
    len += l;
    assert(len <= sizeof(content));
}

ssize_t CBuffer::put(const void *data, size_t size) {
    if(len + size > sizeof(content)){
        abort();
    }

    uint32_t start = (offset + len) % sizeof(content);
    uint32_t finish = (offset +  len + size) % sizeof(content);
    if(finish > start){
        memcpy(content + start, data, size);
    }else{
        size_t l = sizeof(content) - start;
        memcpy(content + start, data, l);
        memcpy(content, (const char*)data + l, finish);
    }
    len += size;
    assert(len <= sizeof(content));
    return (ssize_t)len;
}

Buffer CBuffer::get(){
    uint32_t start = offset % sizeof(content);
    uint32_t finish = (offset + len) % sizeof(content);

    if(finish > start){
        return Buffer{content + start, len};
    }
    Buffer bb{len};
    size_t l = sizeof(content) - start;
    memcpy(bb.mutable_data(), content + start, l);
    memcpy((char*)bb.mutable_data() + l, content, finish);
    bb.truncate(len);
    return bb;
}

void CBuffer::consume(size_t l){
    assert(l <= len);
    offset += l;
    len -= l;
}

char* CBuffer::end(){
    return content + ((offset + len) % sizeof(content));
}

size_t EBuffer::left() const{
    uint32_t start = offset % size;
    uint32_t finish = (offset + len) % size;
    if(finish > start || len == 0){
        return size - finish;
    }
    return start - finish;
}

size_t EBuffer::length() const {
    assert(len <= size);
    return len;
}

size_t EBuffer::cap() const{
    return size - len;
}

void EBuffer::append(size_t l){
    len += l;
    assert(len <= size);
}

void EBuffer::expand(size_t newsize) {
    uint32_t start = offset % size;
    uint32_t finish = (offset + len) % size;

    char *newcontent = new char[newsize];
    if(finish > start){
        put(newcontent, offset, newsize, content + start, len);
    }else if(len > 0){
        size_t l = size - start;
        put(newcontent, offset, newsize, content + start, l);
        put(newcontent, offset + l, newsize, content, finish);
    }

    delete[] content;
    content = newcontent;
    size = newsize;
}

uint64_t EBuffer::put(void* dst, uint64_t pos, size_t size, const void* data, size_t dsize){
    if(dsize == 0){
        return pos;
    }
    assert(dsize <= size);
    uint32_t start = pos  % size;
    uint32_t finish = (pos +  dsize) % size;
    if(finish > start){
        memcpy((char*)dst + start, data, dsize);
    }else{
        size_t l = size - start;
        memcpy((char*)dst + start, data, l);
        memcpy(dst, (const char*)data + l, finish);
    }
    return pos + dsize;
}

ssize_t EBuffer::put(const void *data, size_t sizeofdata) {
    size_t result = len + sizeofdata;
    if(result > MAX_BUF_LEN){
        return -1;
    }
    if(result > size/2){
        expand(std::min(size * 2, (size_t)MAX_BUF_LEN));
    }
    put(content, offset + len, size, data, sizeofdata);
    len = result;
    assert(len <= size);
    return result;
}

Buffer EBuffer::get(){
    return get(len);
}

Buffer EBuffer::get(size_t len) {
    len = std::min(len, this->len);
    assert(len > 0);
    uint32_t start = offset % size;
    uint32_t finish = (offset + len) % size;

    if(finish > start){
        return Buffer{content + start, len};
    }
    Buffer bb{len};
    size_t l = size - start;
    memcpy(bb.mutable_data(), content + start, l);
    memcpy((char*)bb.mutable_data() + l, content, finish);
    bb.truncate(len);
    return bb;
}

void EBuffer::consume(size_t l){
    assert(l <= len);
    offset += l;
    len -= l;
}

char* EBuffer::end(){
    return content + ((offset + len) % size);
}

#include "util.h"
std::string dumpDest(const Destination& addr) {
    return dumpDest(&addr);
}
