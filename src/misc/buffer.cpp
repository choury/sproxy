//
// Created by 周威 on 2022/4/26.
//
#include "buffer.h"
#include "common/common.h"


Buffer::Buffer(size_t len, uint64_t id):
        ptr(std::make_shared<Block>(len)), id(id), len(0), cap(len)
{
    assert(this->ptr != nullptr);
}

Buffer::Buffer(const void* ptr, size_t len, uint64_t id):
        ptr(std::make_shared<Block>(ptr, len)), id(id), len(len), cap(len)
{
    assert(this->ptr != nullptr);
}

Buffer::Buffer(std::shared_ptr<Block> ptr, size_t len, uint64_t id):
        ptr(ptr), id(id), len(len), cap(len)
{
    assert(this->ptr != nullptr);
}

Buffer::Buffer(std::nullptr_t, uint64_t id): id(id){
}

Buffer::Buffer(Buffer&& b){
    assert(b.ptr != nullptr || b.len == 0);
    ptr = b.ptr;
    id = b.id;
    len = b.len;
    cap = b.len;
    b.ptr = nullptr;
    b.id = 0;
    b.cap = 0;
    b.len = 0;
}

void* Buffer::reserve(int off){
    if(ptr == nullptr){
        assert(len == 0);
        ptr = std::make_shared<Block>(0);
    }
    assert((int)len >= off);
    len -= off;
    return ptr->reserve(off);
}

size_t Buffer::truncate(size_t left) {
    size_t origin = len;
    if(left > cap){
        auto new_ptr = std::make_shared<Block>(left);
        memcpy(new_ptr->data(), ptr->data(), len);
        ptr = new_ptr;
        cap = left;
    }
    len = left;
    return origin;
}

void* Buffer::data() const{
    if(ptr == nullptr){
        return nullptr;
    }
    return ptr->data();
}

void* Buffer::end() const {
    if(ptr == nullptr){
        return nullptr;
    }
    return (char*)ptr->data() + len;
}

buff_iterator WBuffer::start() {
    return write_queue.begin();
}

buff_iterator WBuffer::end() {
    return write_queue.end();
}

buff_iterator WBuffer::push(buff_iterator i, Buffer&& bb) {
    len += bb.len;
    return write_queue.emplace(i, std::move(bb));
}

ssize_t WBuffer::Write(std::function<ssize_t(const void*, size_t, uint64_t)> write_func){
    if(write_queue.empty()){
        return 0;
    }
    auto i = write_queue.begin();
    if(i->len == 0){
        ssize_t ret = write_func(nullptr, 0, i->id);
        if(ret < 0){
            return ret;
        }
        write_queue.pop_front();
        return 0;
    }
    ssize_t ret = write_func((const char*)i->data(), i->len, i->id);
    if (ret > 0) {
        assert(len >= (size_t)ret && (size_t)ret <= i->len);
        len -= ret;
        i->reserve(ret);
        if (i->len == 0) {
            write_queue.pop_front();
        }
    }
    return ret;
}

size_t WBuffer::length() {
    return len;
}

WBuffer::~WBuffer() {
    while(!write_queue.empty()){
        write_queue.pop_front();
    }
    len = 0;
}

size_t RBuffer::left(){
    return sizeof(content) - len;
}

size_t RBuffer::length(){
    assert(len <= sizeof(content));
    return len;
}

size_t RBuffer::add(size_t l){
    assert(len + l <= sizeof(content));
    len += l;
    return l;
}

ssize_t RBuffer::put(const void *data, size_t size) {
    if(len + size > sizeof(content)){
        return -1;
    }
    memcpy(content + len, data, size);
    len += size;
    return (ssize_t)len;
}

size_t RBuffer::cap() {
    return sizeof(content) - len;
}

const char* RBuffer::data(){
    return content;
}

size_t RBuffer::consume(size_t l) {
    assert(l <= len);
    len -= l;
    memmove(content, content+l, len);
    return l;
}

char* RBuffer::end(){
    return content+len;
}

size_t CBuffer::left(){
    uint32_t start = offset % sizeof(content);
    uint32_t finish = (offset + len) % sizeof(content);
    if(finish > start || len == 0){
        return sizeof(content) - finish;
    }
    return start - finish;
}

size_t CBuffer::length(){
    assert(len <= sizeof(content));
    return len;
}

size_t CBuffer::cap() {
    return sizeof(content) - len;
}

void CBuffer::add(size_t l){
    len += l;
    assert(len <= sizeof(content));
}

ssize_t CBuffer::put(const void *data, size_t size) {
    if(len + size > sizeof(content)){
        return -1;
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

size_t CBuffer::get(char* buff, size_t size){
    assert(size != 0);
    size = Min(len, size);

    uint32_t start = offset % sizeof(content);
    uint32_t finish = (offset + size) % sizeof(content);

    if(finish > start){
        memcpy(buff, content+ start , size);
        return size;
    }
    size_t l = sizeof(content) - start;
    memcpy(buff, content + start, l);
    memcpy(buff + l, content, finish);
    return size;
}

void CBuffer::consume(size_t l){
    assert(l <= len);
    offset += l;
    len -= l;
}

char* CBuffer::end(){
    return content + ((offset + len) % sizeof(content));
}
