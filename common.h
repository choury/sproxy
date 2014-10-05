#ifndef __CONF_H__
#define __CONF_H__


#include <pthread.h>
#include <list>


extern uint16_t SPORT;
#define CPORT 3333


extern char SHOST[];

#define THREADS 10


#define Min(x,y) ((x)<(y)?(x):(y))

class Peer;
class Guest;
class Host;



class Peerlist:public std::list<Peer *>{
public:
    Peerlist();
    void purge();
};

extern Peerlist peerlist;
extern pthread_mutex_t lock;



#ifdef  __cplusplus
extern "C" {
#endif

char* strnstr(const char* s1, const char* s2, size_t len);

    
#ifdef  __cplusplus
}
#endif

#endif