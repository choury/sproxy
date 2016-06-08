#ifndef ISTRING_H__
#define ISTRING_H__

#include <string.h>
#include <stdlib.h>

#include <string>


class istring {
    size_t len = 0;
    char* str = nullptr;
public:
    istring(){}
    istring(const char *s, size_t length = 0){
        if(length){
            len = length;
        }else{
            len = strlen(s);
        }
        str = (char *)malloc(len+1);
        memcpy(str, s, len);
        str[len] = 0;
    }
    istring(const std::string& s):istring(s.c_str(), s.size()){}
    istring(const istring& is):istring(is.c_str(), is.size()){}
    istring(istring&& is){
        str = is.str;
        len = is.len;
        is.str = nullptr;
    }
    bool operator< (const istring& is) const{
        return strcasecmp(str, is.str) < 0;
    }
    bool operator> (const istring& is) const{
        return strcasecmp(this->str, is.str) > 0;
    }
    bool operator== (const char* s) const{
        return strcasecmp(this->str, s) == 0;
    }
    bool operator== (const istring& is) const{
        return strcasecmp(this->str, is.str) == 0;
    }
    istring& operator=(const istring& is){
        free(str);
        len = is.len;
        str = (char *)malloc(len+1);
        memcpy(str, is.c_str(), len);
        str[len] = 0;
        return *this;
    }
    istring& operator=(istring&& is){
        free(str);
        str = is.str;
        len = is.len;
        is.str = nullptr;
        return *this;
    }
    istring&& operator+(const istring& is) const{
        istring os;
        os.len = this->len+is.len;
        os.str = (char *)malloc(os.len+1);
        strcpy(os.str, str);
        strcat(os.str, is.str);
        return std::move(os);
    }
    char& operator[](size_t index){
        return str[index];
    }
    char operator[](size_t index) const{
        return str[index];
    }
    const char* c_str() const{
        return str;
    }
    size_t length() const{
        return len;
    }
    size_t size() const{
        return len+1;
    }
    ~istring(){
        free(str);
    }
};

#endif
