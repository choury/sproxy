#ifndef __PARSE_H__
#define __PARSE_H__

#include "net.h"
#include <stddef.h>

#include <string>
#include <map>

#define LOADBSUC   "HTTP/1.0 200 Proxy list Loaded" CRLF CRLF
#define ADDBTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF

#define H404       "HTTP/1.0 404 Not Found" CRLF CRLF



void addpsite(const std::string & host);
int loadproxysite();


using std::string;
using std::map;

class Http{
    map<string,string> header;
public:
    char method[20];
    char url[URLLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    bool willproxy=false;
    int port;
    Http(char *header)throw (int);
    int getstring(char *);
    bool ismethod(const char *);
    bool checkproxy();
    string getval(const char *key);
};


size_t parse302(const char *location,char* buff);
size_t parse200(int length,char *buff);




#endif