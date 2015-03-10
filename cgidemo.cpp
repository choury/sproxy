#include <string>
#include <map>

#include <string.h>

#include "parse.h"


using std::map;
using std::string;
int cgimain(const HttpReqHeader *req, HttpResHeader *res){
    res->add("test","yes");
    strcpy(res->status, "200 test");
    res->add("Location","//www.amzon.com");
    res->sendheader();
    char buff[4096];
    for(auto i:req->params){
        sprintf(buff,"%s --> %s\n",i.first.c_str(),i.second.c_str());
        res->write(buff,strlen(buff));
    }
    return 0;
}
