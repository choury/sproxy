#ifndef __PARSE_H__
#define __PARSE_H__

#include "net.h"
#include <stddef.h>

#include <string>
#include <map>

#define LOADBSUC   "HTTP/1.0 200 Proxy list Loaded" CRLF CRLF
#define ADDBTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF

#define H404       "HTTP/1.0 404 Not Found" CRLF CRLF
    
int checkproxy(const char *host);
void addpsite(const std::string & host);
int loadproxysite();

using std::string;
using std::map;
map<string, string> parse(char* header);
size_t parse302(const char *location,char* buff);
size_t parse200(int length,char *buff);
int gheaderstring(std::map<std::string,std::string> &,char *);

int spliturl(const char* url, char* hostname, char* path , int* port);



#endif