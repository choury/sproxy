//
// Created by choury on 2022/4/26.
//
#include "buffer.h"
#include "common/common.h"

#include <string>

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
    } else {
        ptr.reset();
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
    if(off + p < 0) {
        abort();
    }
    off += p;
}

size_t Buffer::truncate(size_t left) {
    size_t origin = len;
    if(ptr) {
        if(off + left <= cap) {
            len = left;
            return origin;
        }
        off_t new_offset = std::max(off, (off_t)PRIOR_HEAD);
        cap = left + new_offset;
        auto new_ptr = std::shared_ptr<void>(malloc(cap), free);
        memcpy((char*)new_ptr.get() + new_offset, (char*)ptr.get() + off, len);
        ptr = new_ptr;
        off = new_offset;
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

size_t CBuffer::length() const{
    return total_len;
}

size_t CBuffer::cap() const{
    return MAX_BUF_LEN - total_len;
}

bool CBuffer::empty() const{
    return buffers.empty();
}

ssize_t CBuffer::put(Buffer&& bb) {
    if(total_len + bb.len > MAX_BUF_LEN){
        abort();
    }

    total_len += bb.len;
    buffers.push_back(std::move(bb));
    return (ssize_t)total_len;
}

Buffer CBuffer::get(){
    if(buffers.empty()){
        return Buffer{nullptr};
    }

    if(buffers.size() == 1){
        return buffers.front();
    }

    if(buffers.front().len == 0){
        return Buffer{nullptr, buffers.front().id};
    }

    uint64_t current_id = buffers.front().id;
    size_t concat_len = 0;

    for(const auto& buf : buffers){
        if(buf.len == 0 && concat_len > 0){
            break;
        }
        if(buf.id != current_id && concat_len > 0){
            break;
        }
        concat_len += buf.len;
    }

    Buffer result{concat_len, current_id};
    size_t pos = 0;
    for(const auto& buf : buffers){
        if(buf.len == 0 && pos > 0){
            break;
        }
        if(buf.id != current_id && pos > 0){
            break;
        }
        if(buf.len > 0){
            memcpy((char*)result.mutable_data() + pos, buf.data(), buf.len);
            pos += buf.len;
        }
    }
    result.truncate(concat_len);
    return result;
}

const std::deque<Buffer>& CBuffer::data() const {
    return buffers;
}

std::set<uint64_t> CBuffer::consume(size_t l){
    assert(l <= total_len);
    total_len -= l;

    std::set<uint64_t> ids;
    while(!buffers.empty() && buffers.front().len == 0) {
        ids.emplace(buffers.front().id);
        buffers.pop_front();
    }
    size_t remaining = l;
    while(remaining > 0 && !buffers.empty()){
        Buffer& front = buffers.front();
        ids.emplace(front.id);
        if(front.len <= remaining){
            remaining -= front.len;
            buffers.pop_front();
        }else{
            front.reserve((int)remaining);
            break;
        }
    }
    return ids;
}

size_t EBuffer::left() const{
    uint32_t start = ranges[0].start % capacity;
    uint32_t finish = ranges[0].end % capacity;
    if(finish > start || ranges[0].start == ranges[0].end){
        return capacity - finish;
    }
    return start - finish;
}

size_t EBuffer::length() const {
    return ranges.back().end - ranges[0].start;
}

size_t EBuffer::cap() const{
    return capacity - length();
}

void EBuffer::append(size_t l){
    ranges.back().end += l;
    assert(length() <= capacity);
}

void EBuffer::expand(size_t newsize) {
    uint32_t start = ranges[0].start % capacity;
    uint32_t finish = ranges.back().end % capacity;

    auto len = length();
    char *newcontent = new char[newsize];
    if(finish > start){
        put(newcontent, ranges[0].start, newsize, content + start, len);
    }else if(len > 0){
        size_t l = capacity - start;
        put(newcontent, ranges[0].start, newsize, content + start, l);
        put(newcontent, ranges[0].start + l, newsize, content, finish);
    }

    delete[] content;
    content = newcontent;
    capacity = newsize;
}

size_t EBuffer::put(void* dst, size_t pos, size_t size, const void* data, size_t dsize){
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
    return put_at(ranges.back().end, data, sizeofdata);
}

ssize_t EBuffer::put_at(size_t pos, const void *data, size_t sizeofdata) {
    if(sizeofdata == 0) {
        return length();
    }

    // 检查是否会超出最大缓冲区大小
    size_t end_pos = pos + sizeofdata;
    if(end_pos > MAX_BUF_LEN + ranges[0].start) {
        return -1;
    }

    // 如果put_at的位置在当前偏移量之前，只处理重叠部分
    size_t effective_start = std::max(pos, ranges[0].start);
    if(effective_start >= end_pos) {
        // 没有有效数据需要写入
        return length();
    }

    // 计算需要的缓冲区大小
    size_t needed_size = end_pos - ranges[0].start;
    if(needed_size >= capacity) {
        size_t new_size = capacity;
        while(new_size <= needed_size && new_size < MAX_BUF_LEN) {
            new_size *= 2;
        }
        if(new_size > MAX_BUF_LEN) {
            new_size = MAX_BUF_LEN;
        }
        expand(new_size);
    }

    // 写入数据，但只写入有效范围内的数据
    size_t data_offset = effective_start - pos;
    size_t effective_size = end_pos - effective_start;
    put(content, effective_start, capacity, (const char*)data + data_offset, effective_size);

    // 合并数据范围
    merge_ranges(effective_start, end_pos);
    return length();
}

void EBuffer::merge_ranges(size_t start, size_t end) {
    if(start >= end) {
        return;
    }

    DataRange new_range(start, end);

    // 找到需要合并的范围
    std::vector<DataRange> merged;
    bool inserted = false;

    for(const auto& range : ranges) {
        if(range.end < start) {
            // 在新范围之前，直接添加
            merged.push_back(range);
        } else if(range.start > end) {
            // 在新范围之后
            if(!inserted) {
                merged.push_back(new_range);
                inserted = true;
            }
            merged.push_back(range);
        } else {
            // 有重叠或相邻，需要合并
            new_range.start = std::min(new_range.start, range.start);
            new_range.end = std::max(new_range.end, range.end);
        }
    }

    if(!inserted) {
        merged.push_back(new_range);
    }
    ranges = std::move(merged);
}

// 只获取从头开始的连续数据
Buffer EBuffer::get(size_t request_len) {
    return get_at(ranges[0].start, request_len);
}

Buffer EBuffer::get_at(size_t pos, size_t len) {
    if(len == 0) {
        return Buffer{nullptr};
    }

    // 检查连续数据的长度，只返回实际有数据的部分
    size_t continuous_len = continuous_length_at(pos);
    size_t actual_len = std::min(len, continuous_len);
    if(actual_len == 0) {
        return Buffer{nullptr};
    }

    uint32_t start = pos % capacity;
    uint32_t finish = (pos + actual_len) % capacity;

    if(finish > start){
        return Buffer{content + start, actual_len};
    }
    Buffer bb{actual_len};
    size_t l = capacity - start;
    memcpy(bb.mutable_data(), content + start, l);
    memcpy((char*)bb.mutable_data() + l, content, finish);
    bb.truncate(actual_len);
    return bb;
}

void EBuffer::consume(size_t l){
    if(l == 0) {
        return;
    }
    size_t new_offset = ranges[0].start + l;

    // 更新 ranges，删除已经被消费的部分
    std::vector<DataRange> new_ranges;
    for(const auto& range : ranges) {
        if(range.end <= new_offset) {
            // 这个范围完全被消费了
            continue;
        }
        if(range.start < new_offset) {
            // 这个范围部分被消费了
            if(new_offset < range.end) {
                new_ranges.emplace_back(new_offset, range.end);
            }
        } else {
            // 这个范围完全保留
            new_ranges.push_back(range);
        }
    }

    // 如果没有剩余数据，或者第一个范围不是从new_offset开始，添加空范围来维护偏移量
    if(new_ranges.empty() || new_ranges[0].start != new_offset) {
        new_ranges.insert(new_ranges.begin(), DataRange(new_offset, new_offset));
    }
    ranges = std::move(new_ranges);
}

char* EBuffer::end(){
    return content + ranges.back().end % capacity;
}

const std::vector<DataRange>& EBuffer::get_ranges() const {
    return ranges;
}

size_t EBuffer::continuous_length() const {
    return ranges[0].end - ranges[0].start;
}

size_t EBuffer::continuous_length_at(size_t pos) const {
    for(const auto& range : ranges) {
        if(pos >= range.start && pos < range.end) {
            return range.end - pos;
        }
    }
    return 0;
}

#include "util.h"
std::string dumpDest(const Destination& addr) {
    return dumpDest(&addr);
}
