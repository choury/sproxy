#ifndef CURSOR_H__
#define CURSOR_H__
#include <string.h>
// 类似于std::span，协议解析与打包共用的缓冲区游标

class cursor{
    //pos/size 为 private：位置与剩余长度只能经由 advance 移动，
    //读取走 data()/length()，写入缓冲走 mutable_data()
    mutable unsigned char* pos;
    mutable size_t size;
public:
    //从 const 缓冲构造的游标仅限解码路径使用：本类的写入接口(mutable_data及
    //HttpCursor的encode系列)只允许作用于经 void* 构造的可写游标，故此处置弃
    //const 是安全的
    cursor(const void* ptr, size_t size):
        pos(static_cast<unsigned char*>(const_cast<void*>(ptr))), size(size) {}
    cursor(void* ptr, size_t size):
        pos(static_cast<unsigned char*>(ptr)), size(size) {}
    //可拷贝(用于派生子游标)，但不可对既有游标赋值重定位
    cursor(const cursor&) = default;
    cursor& operator=(const cursor&) = delete;

    const unsigned char* data() const { return pos; }
    unsigned char* mutable_data() { return pos; }
    size_t length() const { return size; }
    bool empty() const { return size == 0; }
    //推进n字节，越界返回false；n为0是合法的空推进(空游标上亦成功)
    bool advance (size_t n) const {
        if(n > size) {
            return false;
        }
        pos += n;
        size -= n;
        return true;
    }
    //读取固定宽度结构并推进游标；空间不足返回nullptr
    template<typename T>
    const T* read() const {
        if(length() < sizeof(T)){
            return nullptr;
        }
        const T* v = (const T*)data();
        advance(sizeof(T));
        return v;
    }
    //在游标处写入一个零初始化的T并推进，返回指针供逐字段填充；空间不足返回nullptr
    //零初始化是为了位域/联合等逐字段填充时不会把内存残值写进输出报文
    template<typename T>
    T* write() {
        if(length() < sizeof(T)){
            return nullptr;
        }
        T* v = (T*)mutable_data();
        memset(v, 0, sizeof(T));
        advance(sizeof(T));
        return v;
    }
    //写入完整值并推进游标(整体覆盖，无需零初始化)；空间不足返回false
    template<typename T>
    bool write(const T& v) {
        if(length() < sizeof(T)){
            return false;
        }
        *(T*)mutable_data() = v;
        advance(sizeof(T));
        return true;
    }
    //写入len字节并推进游标；空间不足返回false，len为0时容忍空指针
    bool write_data(const void* data, size_t len) {
        if(len == 0){
            return true;
        }
        if(length() < len){
            return false;
        }
        memcpy(mutable_data(), data, len);
        advance(len);
        return true;
    }
};

#endif
