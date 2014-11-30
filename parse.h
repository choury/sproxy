#ifndef __PARSE_H__
#define __PARSE_H__

#include "net.h"
#include <stddef.h>

#include <string>
#include <map>

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
    int getstring(void* buff, protocol prot);
    bool ismethod(const char *);
    const char* getval(const char *key);
};

class HttpResHeader{
    map<string,string> header;
public:
    char version[20];
    char status[100];
    HttpResHeader(char* status);
    void add(const char *header,const char *value);
    void del(const char *header);
    const char* getval(const char *key);
    int getstring(char *,protocol proto);
};


#endif