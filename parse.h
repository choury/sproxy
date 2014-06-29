#ifndef __PARSE_H__
#define __PARSE_H__

#ifdef  __cplusplus
extern "C" {
#endif

int checkblock(const char *host);
void prepareheader(char *header,const char *host,int port);
void parse(char* header);
    
#ifdef  __cplusplus
}
#endif

#endif