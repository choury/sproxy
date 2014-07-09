#ifndef __PARSE_H__
#define __PARSE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define LOADBSUC  "HTTP/1.0 200 Block list Loaded" CRLF CRLF
#define LOADBFAIL "HTTP/1.0 404 Block list not found" CRLF CRLF

#define ADDBTIP   "HTTP/1.0 200 Block site Added" CRLF CRLF
    
int checkblock(const char *host);
void parse(char* header);
void addbsite(const char *host);
int loadblocksite();
    
#ifdef  __cplusplus
}
#endif

#endif