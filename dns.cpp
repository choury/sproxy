#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
//#include <resolv.h>
#include <sys/epoll.h>
#include <unordered_map>
#include <string>

#include "common.h"
#include "dns.h"
#include "net.h"


#define BUF_SIZE 1024

#define HTON(x) (x=nton(x))
#define HTONS(x) (x=ntons(x))


#define NTOH(x) (x=ntoh(x))
#define NTOHS(x) (x=ntohs(x))

typedef unsigned short uint16;
typedef unsigned int   uint32;


static unsigned int id_cur=0;

std::vector<Dns_srv *> srvs;


typedef struct _DNS_HDR {
    uint16 id;                 //查询序列号
    uint16 flag;
#define  QR 0x8000          //查询/应答 0/1
#define  OPCODE_STD 0       //0:标准查询
#define  OPCODE_STR 0x0800  //1:反向查询
#define  OPCODE_STA 0x1000  //2:查询服务器状态
#define  AA 0x0400          //授权应答标志
#define  TC 0x0200          //截断标志
#define  RD 0x0100          //递归查询标志
#define  RA 0x0080          //允许递归标志
#define  RCODE_MASK 0x000F  //应答码
    //0 没有错误。
    //1 报文格式错误(Format error) - 服务器不能理解请求的报文。
    //2 服务器失败(Server failure) - 因为服务器的原因导致没办法处理这个请求。
    //3 名字错误(Name Error) - 只有对授权域名解析服务器有意义，指出解析的域名不存在。
    //4 没有实现(Not Implemented) - 域名服务器不支持查询类型。
    //5 拒绝(Refused) - 服务器由于设置的策略拒绝给出应答。比如，服务器不希望对某些请求者给出应答，或者服务器不希望进行某些操作（比如区域传送zone transfer）。
    //6-15 保留值，暂时未使用。
    uint16 numq;               //问题个数
    uint16 numa;               //应答资源个数
    uint16 numa1;              //授权记录数
    uint16 numa2;              //额外资源记录数
} __attribute__ ((packed)) DNS_HDR;
typedef struct _DNS_QER {
    uint16 type;               //类型A，值是1，表示获取目标主机的IP地址。
    //类型CNAME，值是5，表示获得目标主机的别名。
    //类型PTR，值是12，表示反向查询。
    //类型aaaa，值是28，表示查询IPV6地址
    uint16 classes;            //通常为1，表示获取因特网地址（IP地址）
} __attribute__ ((packed)) DNS_QER;


typedef struct _DNS_RR {
    uint16 type;
    uint16 classes;
    uint32 TTL;                //缓存时间
    uint16 rdlength;           //rdata 长度
} __attribute__ ((packed)) DNS_RR;

typedef struct _DNS_STATE{
    unsigned int id;
    time_t reqtime;
    DNSCBfunc func;
    void *param;
    enum {querya,queryaaaa}status;
    char host[DOMAINLIMIT];
    std::vector<sockaddr_un> addr;
}DNS_STATE;

std::unordered_map<int,DNS_STATE *> rcd_index_id;
std::unordered_map<std::string,Dns_rcd> rcd_index_host;

unsigned char * getdomain(unsigned char *buf,unsigned char *p) {
    while(*p) {
        if(*p>63) {
            unsigned char *q=buf+(((*p)<< 8 | *(p+1) )&0x3fff);
            getdomain(buf,q);
            return p+2;
        } else {
//            printf("%.*s.",*p,p+1);
            p+=*p+1;
        }
    }
    return p+1;
}


unsigned char *getrr(unsigned char *buf,unsigned char *p,int num,std::vector<sockaddr_un>& addr) {
    int i;
    for(i=0; i<num; ++i) {
        p=getdomain(buf,p);
        DNS_RR *dnsrr=(DNS_RR *)p;
        NTOHS(dnsrr->type);
        NTOHS(dnsrr->classes);
        NTOHS(dnsrr->TTL);
        NTOHS(dnsrr->rdlength);
        p+=sizeof(DNS_RR);
//        printf(" ==> ");
        switch(dnsrr->type) {
//            char ipaddr[INET6_ADDRSTRLEN];
            sockaddr_un ip;
        case 1:
            ip.addr_in.sin_family=PF_INET;
            memcpy(&ip.addr_in.sin_addr,p,sizeof(in_addr));
            addr.push_back(ip);
//            printf("%s",inet_ntop(PF_INET,p,ipaddr,sizeof(ipaddr)));
            break;
        case 2:
        case 5:
            getdomain(buf,p);
            break;
        case 28:
            ip.addr_in6.sin6_family=PF_INET6;
            memcpy(&ip.addr_in6.sin6_addr,p,sizeof(in6_addr));
            addr.push_back(ip);
//            printf("%s",inet_ntop(PF_INET6,p,ipaddr,sizeof(ipaddr)));
            break;
        }
        p+=dnsrr->rdlength;
//        printf("\n");
    }
    return p;
}

int dnsinit(int efd) {
    struct epoll_event event;
    event.events=EPOLLIN ;
    for(size_t i=0; i<srvs.size(); ++i) {
        close(srvs[i]->fd);
        delete srvs[i];
    }
    srvs.clear();
    
    FILE *res_file=fopen(_RESOLV_FILE_,"r");
    if(res_file==NULL) {
        LOGE("[DNS] open resolv file:%s failed:%s\n",_RESOLV_FILE_,strerror(errno) );
        return -1;
    }
    char *line=NULL;
    size_t len=0;
    while(getline(&line,&len,res_file)!=-1){
        char command[11],ipaddr[INET6_ADDRSTRLEN];
        sscanf(line,"%10s %45s",command,ipaddr);
        if(strcmp(command,"nameserver")==0){
            sockaddr_un addr;
            if(inet_pton(PF_INET,ipaddr,&addr.addr_in.sin_addr)==1){
                addr.addr_in.sin_family=PF_INET;
                addr.addr_in.sin_port=htons(DNSPORT);
                Dns_srv *srv= new Dns_srv;
                if ( ( srv->fd  =  socket (PF_INET, SOCK_DGRAM, 0 ) )  <   0 ) {
                    LOGE( "[DNS] create socket error:%s\n",strerror(errno) );
                    delete srv;
                    continue;
                }
                if (connect(srv->fd,&addr.addr,sizeof(sockaddr_in)) == -1) {
                    LOGE("[DNS] connecting %s error:%s\n",ipaddr,strerror(errno));
                    close(srv->fd);
                    delete srv;
                    continue;
                }
                srvs.push_back(srv);
                event.data.ptr=srv;
                epoll_ctl(efd, EPOLL_CTL_ADD,srv->fd,&event);
            }else if(inet_pton(PF_INET6,ipaddr,&addr.addr_in6.sin6_addr)==1){
                addr.addr_in6.sin6_family=PF_INET6;
                addr.addr_in6.sin6_port=htons(DNSPORT);
                Dns_srv *srv=new Dns_srv;
                if ( ( srv->fd  =  socket (PF_INET6, SOCK_DGRAM, 0 ) )  <   0 ) {
                    LOGE ( "[DNS] create socket error:%s",strerror(errno) );
                    delete srv;
                    continue;
                }
                if (connect(srv->fd,&addr.addr,sizeof(sockaddr_in6)) == -1) {
                    LOGE("[DNS] connecting  %s error:%s\n",ipaddr,strerror(errno));
                    close(srv->fd);
                    delete srv;
                    continue;
                }
                srvs.push_back(srv);
                event.data.ptr=srv;
                epoll_ctl(efd, EPOLL_CTL_ADD,srv->fd,&event);
            }else{
                LOGE("[DNS] %s is not a valid ip address\n",ipaddr);
            }
        }
    }
    free(line);
    fclose(res_file);
    return srvs.size();
}

int query(const char *host ,DNSCBfunc func,void *param) {
    unsigned char buf[BUF_SIZE];
    if(inet_pton(PF_INET,host,buf)==1){
        sockaddr_un addr;
        addr.addr_in.sin_family=PF_INET;
        memcpy(&addr.addr_in.sin_addr,buf,sizeof(in_addr));
        func(param,Dns_rcd(addr));
        return 0;
    }
    
    if(inet_pton(PF_INET6,host,buf)==1){
        sockaddr_un addr;
        addr.addr_in6.sin6_family=PF_INET6;
        memcpy(&addr.addr_in6.sin6_addr,buf,sizeof(in6_addr));
        func(param,Dns_rcd(addr));
        return 0;
    }
    
    if(rcd_index_host.find(host) != rcd_index_host.end()){
        func(param,rcd_index_host[host]);
        return 0;
    }

    DNS_STATE *dnsst = new DNS_STATE;
    dnsst->id=id_cur++;
    dnsst->func=func;
    dnsst->param=param;
    dnsst->status=DNS_STATE::querya;
    strcpy(dnsst->host,host);
    
    for(size_t i=0;i<srvs.size();++i){
        dnsst->id=srvs[i]->query(host,1);
        if(dnsst->id != 0){
            dnsst->reqtime=time(nullptr);
            rcd_index_id[dnsst->id]=dnsst;
            return 0;
        }
    }
    delete dnsst;
    return -1;
}




void Dns_srv::handleEvent(uint32_t events) {
    unsigned char buf[BUF_SIZE];
    if (events & EPOLLIN) {
        int len = read( fd, buf,BUF_SIZE);

        if ( len <= 0 ) {
            perror("[DNS] read");
            return;
        }
        DNS_HDR *dnshdr=(DNS_HDR *)buf;
        NTOHS(dnshdr->id);
        NTOHS(dnshdr->flag);
        NTOHS(dnshdr->numq);
        NTOHS(dnshdr->numa);
        NTOHS(dnshdr->numa1);
        NTOHS(dnshdr->numa2);
        
        if(rcd_index_id.find(dnshdr->id) == rcd_index_id.end()){
            LOGE("[DNS] Get a unkown id:%d\n",dnshdr->id);
            return;
        }
        DNS_STATE *dnsst=rcd_index_id[dnshdr->id];
        rcd_index_id.erase(dnsst->id);
        
        if ( (dnshdr->flag & QR) == 0 || (dnshdr->flag & RCODE_MASK) != 0) {
            LOGE("[DNS] ack error:%u\n", dnshdr->flag & RCODE_MASK);
            if(dnsst->status==DNS_STATE::querya){
                dnsst->func(dnsst->param,Dns_rcd(DNS_ERR));
                delete dnsst;
                return;
            }
        }else{
            unsigned char *p = buf+sizeof(DNS_HDR);
            for(int i=0; i<dnshdr->numq; ++i) {
                p=getdomain(buf,p);
                p+=sizeof(DNS_QER);
            }
            getrr(buf,p,dnshdr->numa,dnsst->addr);
        }
        
        if(dnsst->status==DNS_STATE::querya){
            dnsst->status=DNS_STATE::queryaaaa;
            for(size_t i=0;i<srvs.size();++i){
                dnsst->id=srvs[i]->query(dnsst->host,28);
                if(dnsst->id != 0){
                    dnsst->reqtime=time(nullptr);
                    rcd_index_id[dnsst->id]=dnsst;
                    return;
                }
            }
        }
        if(dnsst->addr.size()){
            dnsst->func(dnsst->param,Dns_rcd(dnsst->addr));
        }else{
            dnsst->func(dnsst->param,Dns_rcd(DNS_ERR));
        }
        delete dnsst;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("[DNS] : %s\n",strerror(error));
        }
    }
}


int Dns_srv::query(const char *host, int type){
    unsigned char  buf[BUF_SIZE];
    unsigned char  *p;
    DNS_HDR  *dnshdr = ( DNS_HDR * )buf;
    unsigned int id=id_cur++;
    memset ( buf, 0, BUF_SIZE );
    dnshdr->id = htons(id);
    dnshdr->flag = htons(RD);
    dnshdr->numq = htons (1);

    p = buf + sizeof ( DNS_HDR ) + 1;
    strcpy ( (char *)p, host);

    int i = 0;
    while ( p < ( buf + sizeof ( DNS_HDR ) + 1 + strlen ( host ) ) ) {
        if ( *p == '.' ) {
            * ( p - i - 1 ) = i;
            i = 0;
        } else {
            i++;
        }
        p++;
    }
    * ( p - i - 1 ) = i;

    DNS_QER  *dnsqer = ( DNS_QER * ) ( buf + sizeof ( DNS_HDR ) );
    dnsqer = ( DNS_QER * ) ( buf + sizeof ( DNS_HDR ) + 2 + strlen ( host ) );
    dnsqer->classes = htons(1);
    dnsqer->type = htons(type);


    int len =sizeof ( DNS_HDR ) + sizeof ( DNS_QER ) + strlen ( host ) + 2;
    if(write(fd, buf, len)!=len) {
        perror("[DNS] write");
        return 0;
    }
    return id;
}

