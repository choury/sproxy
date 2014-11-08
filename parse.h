#ifndef __PARSE_H__
#define __PARSE_H__

#include "net.h"
#include <stddef.h>

#include <string>
#include <map>

#define LOADBSUC   "HTTP/1.0 200 Proxy list Loaded" CRLF CRLF
#define ADDBTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF
#define DELBTIP    "HTTP/1.0 200 Proxy site Deleted" CRLF CRLF
#define EGLOBLETIP  "HTTP/1.0 200 Global proxy enabled now" CRLF CRLF
#define DGLOBLETIP  "HTTP/1.0 200 Global proxy disabled" CRLF CRLF


#define H302    "302 Found"
#define H200    "200 OK"
#define H404    "404 Not Found"



void addpsite(const std::string & host);
int delpsite(const std::string &host);
int loadproxysite();
int globalproxy();

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
    HttpReqHeader(char *header,protocol proto)throw (int);
    int getstring(char *,bool shouldproxy=false);
    bool ismethod(const char *);
    bool checkproxy();
    string getval(const char *key);
};

class HttpResHeader{
    map<string,string> header;
public:
    char status[100];
    HttpResHeader(const char* status);
    void add(const char *header,const char *value);
    void del(const char *header);
    int getstring(char *,protocol proto);
};


#endif