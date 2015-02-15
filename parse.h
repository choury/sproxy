#ifndef __PARSE_H__
#define __PARSE_H__

#include <stddef.h>
#include <string>
#include <map>
#include "net.h"
#include "spdy_type.h"
#include "spdy_zlib.h"


void addpsite(const std::string& host);
void addbsite(const std::string& host);
int delpsite(const std::string& host);
int delbsite(const std::string& host);
int globalproxy();
char* toLower(char* s);
char* toUpper(char* s);
bool checkproxy(const char *hostname);
bool checkblock(const char *hostname);

using std::string;
using std::map;


enum protocol{HTTP,SPDY};

class HttpReqHeader{
    map<string,string> header;
public:
    uint32_t id;  //仅由spdy协议使用
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    uint16_t port;
    HttpReqHeader();
    HttpReqHeader(const char* header);
    HttpReqHeader(const syn_frame* sframe,z_stream* instream);
    bool ismethod(const char* method);
    void del(const char *header);
    const char* get(const char *header);
    void add(const char *header,const char *value);
    int getstring(void* outbuff);
    int getframe(void* buff, z_stream* destream);
};

class HttpResHeader{
    map<string,string> header;
public:
    uint32_t id;  //仅由spdy协议使用
    char version[20];
    char status[100];
    HttpResHeader();
    HttpResHeader(const char* header);
    HttpResHeader(const syn_reply_frame *sframe,z_stream* instream);
    void del(const char *header);
    const char* get(const char *header);
    void add(const char *header,const char *value);
    int getstring(void* buff);
    int getframe(void* buff, z_stream* destream);
};


#endif