//
// Created by 周威 on 2022/4/26.
//
#include "buffer.h"
#include "common/common.h"


Buffer::Buffer(size_t cap, uint64_t id):
        ptr(std::make_shared<Block>(cap)), id(id), len(0), cap(cap + PRIOR_HEAD)
{
    assert(this->ptr != nullptr);
}


Buffer::Buffer(const void* data, size_t len, uint64_t id):
        ptr(nullptr), content(data), id(id), len(len), cap(len)
{
    assert(content != nullptr && len != 0);
}

Buffer::Buffer(std::shared_ptr<Block> data, size_t len, uint64_t id):
        ptr(std::move(data)), id(id), len(len), cap(len + ptr->tell())
{
    assert(this->ptr != nullptr);
}

Buffer::Buffer(std::nullptr_t, uint64_t id): id(id){
}

Buffer::Buffer(Buffer&& b) noexcept{
    assert(b.ptr != nullptr || b.content != nullptr || b.len == 0);
    id = b.id;
    len = b.len;
    cap = b.cap;
    if(b.ptr != nullptr){
        ptr = std::move(b.ptr);
        b.id = 0;
        b.cap = 0;
        b.len = 0;
    } else {
        content = b.content;
    }
}

const void* Buffer::reserve(int off){
    if(off == 0) {
        return data();
    }
    if(ptr == nullptr && off < 0){
        ptr = std::make_shared<Block>(content, len);
        content = nullptr;
    }
    assert(off <= (int)len);
    len -= off;
    if (content) {
        content = (char*)content + off;
        return content;
    }
    if(ptr.use_count() > 1){
        ptr = std::make_shared<Block>(ptr->reserve(off), len);
        return ptr->data();
    } else {
        return ptr->reserve(off);
    }
}

size_t Buffer::truncate(size_t left) {
    size_t origin = len;
    if(ptr) {
        if(left + ptr->tell() <= cap) {
            len = left;
            return origin;
        }
        auto new_ptr = std::make_shared<Block>(left);
        memcpy(new_ptr->data(), ptr->data(), std::min(len, left));
        ptr = new_ptr;
    }else {
        if(left <= cap) {
            len = left;
            return origin;
        }
        ptr = std::make_shared<Block>(left);
        memcpy(ptr->data(), content, std::min(len, left));
        content = nullptr;
    }
    cap = left + ptr->tell();
    len = left;
    return origin;
}

const void* Buffer::data() const{
    if(ptr == nullptr){
        return content;
    }
    return ptr->data();
}

void* Buffer::mutable_data() {
    if(ptr == nullptr){
        ptr = std::make_shared<Block>(content, len);
    }
    if(ptr.use_count() > 1) {
        ptr = std::make_shared<Block>(ptr->data(), len);
    }
    return ptr->data();
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

ssize_t WBuffer::Write(const std::function<ssize_t(const Buffer& bb)>& write_func, std::set<uint64_t>& writed_list){
    if(write_queue.empty()){
        return 0;
    }
    auto i = write_queue.begin();
    if(i->len == 0){
        ssize_t ret = write_func({nullptr, i->id});
        if(ret < 0){
            return ret;
        }
        writed_list.insert(i->id);
        write_queue.pop_front();
        return 0;
    }
    ssize_t ret = write_func({i->data(), i->len, i->id});
    if (ret > 0) {
        assert(len >= (size_t)ret && (size_t)ret <= i->len);
        len -= ret;
        i->reserve(ret);
        writed_list.insert(i->id);
        if (i->len == 0) {
            write_queue.pop_front();
        }
    }
    return ret;
}

size_t WBuffer::length() const {
    return len;
}

WBuffer::~WBuffer() {
    while(!write_queue.empty()){
        write_queue.pop_front();
    }
    len = 0;
}

#if 0
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
#endif

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
    if(result > size/2 && size < MAX_BUF_LEN){
        expand(std::min(size * 2, (size_t)MAX_BUF_LEN));
    }
    put(content, offset + len, size, data, sizeofdata);
    len = result;
    assert(len <= size);
    return result;
}

Buffer EBuffer::get(){
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
