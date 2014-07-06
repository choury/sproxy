#ifndef __PARSE_H__
#define __PARSE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define LOADEDTIP "HTTP/1.0 200 Block list Loaded" CRLF CRLF
    
int checkblock(const char *host);
void parse(char* header);
void loadblocksite();
    
#ifdef  __cplusplus
}
#endif

#endif