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

#define H404       "HTTP/1.0 404 Not Found" CRLF CRLF



void addpsite(const std::string & host);
int delpsite(const std::string &host);
int loadproxysite();
int globalproxy();

using std::string;
using std::map;


enum protocol{HTTP,SPDY};

class Http{
    map<string,string> header;
public:
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    uint16_t port;
    Http(char *header,protocol proto)throw (int);
    int getstring(char *,bool);
    bool ismethod(const char *);
    bool checkproxy();
    string getval(const char *key);
};


size_t parse302(const char *location,char* buff);
size_t parse200(int length,char *buff);




#endif