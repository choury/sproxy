#include <map>
#include <string>
#include <string.h>
#include <iostream>

#include "parse.h"
#include "net.h"

using namespace std;

int checkblock(const char *host){
    return 1;
}

void prepareheader(char *header,const char *host,int port){
    
}

void parse(char* header)
{
    map<string, string> hmap;
    strcpy(header, header);
    for (char *str = header; ; str = NULL) {
        char *p = strtok(str, CRLF);
        if (p == NULL)
            break;
        char * sp=strpbrk(p,":");
        hmap[string(p,sp-p)]=string(sp+1);
    }
    
    hmap.erase("DNT");
    
    int p=0;
    for(auto i:hmap){
        int len;
        sprintf(header+p,"%s:%s" CRLF "%n",i.first.c_str(),i.second.c_str(),&len);
        p+=len;
    }
    sprintf(header+p,CRLF);
    
    cout<<header;
}
