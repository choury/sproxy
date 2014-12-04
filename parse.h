#ifndef __PARSE_H__
#define __PARSE_H__

#include <stddef.h>
#include <string>
#include <map>
#include "net.h"
#include "spdy_type.h"
#include "spdy_zlib.h"


#define ADDBTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF
#define DELBTIP    "HTTP/1.0 200 Proxy site Deleted" CRLF CRLF
#define DELFTIP    "HTTP/1.0 404 The site is not found" CRLF CRLF
#define EGLOBLETIP  "HTTP/1.0 200 Global proxy enabled now" CRLF CRLF
#define DGLOBLETIP  "HTTP/1.0 200 Global proxy disabled" CRLF CRLF


#define H302    "302 Found"
#define H200    "200 OK"
#define H404    "404 Not Found"



void addpsite(const std::string & host);
int delpsite(const std::string &host);
int loadproxysite();
int globalproxy();
char* toLower(char* s);
char* toUpper(char* s);
bool checkproxy(const char *hostname);

using std::string;
using std::map;


enum protocol{HTTP,SPDY};

class HttpReqHeader{
    map<string,string> header;
public:
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    uint16_t port;
    HttpReqHeader(uchar* header)throw (int);
    HttpReqHeader(syn_frame* sframe,z_stream* instream);
    bool ismethod(const char* method);
    const char* getval(const char *key);
    int getstring(void* outbuff);
    int getframe(void* buff, z_stream* destream, size_t id);
};

class HttpResHeader{
    map<string,string> header;
public:
    char version[20];
    char status[100];
    HttpResHeader(char* status);
    HttpResHeader(syn_reply_frame *sframe,z_stream* instream);
    void add(const char *header,const char *value);
    void del(const char *header);
    const char* getval(const char *key);
    int getstring(void* buff);
    int getframe(void* buff, z_stream* destream, size_t id);
};


#endif