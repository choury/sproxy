/*
JUST FOR TEST

*/


#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 1024
#define SRV_PORT 53

#define HTON(x) (x=nton(x))
#define HTONS(x) (x=ntons(x))


#define NTOH(x) (x=ntoh(x))
#define NTOHS(x) (x=ntohs(x))

typedef unsigned short U16;
typedef unsigned int   U32;

const char srv_ip[] = "10.72.55.103";

typedef struct _DNS_HDR {
    U16 id;                 //查询序列号
    U16 flag;
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
    U16 numq;               //问题个数
    U16 numa;               //应答资源个数
    U16 numa1;              //授权记录数
    U16 numa2;              //额外资源记录数
} __attribute__ ((packed)) DNS_HDR;
typedef struct _DNS_QER {
    U16 type;               //类型A，值是1，表示获取目标主机的IP地址。
    //类型CNAME，值是5，表示获得目标主机的别名。
    //类型PTR，值是12，表示反向查询。
    //0xFF 表示查询全部
    U16 classes;            //通常为1，表示获取因特网地址（IP地址）
} __attribute__ ((packed)) DNS_QER;


typedef struct _DNS_RR {
    U16 type;
    U16 classes;
    U32 TTL;                //缓存时间
    U16 rdlength;           //rdata 长度
} __attribute__ ((packed)) DNS_RR;


unsigned char * getdomain(const unsigned char *buf,const unsigned char *p) {
    while(*p) {
        if(*p>63) {
            unsigned char *q=buf+(((*p)<< 8 | *(p+1) )&0x3fff);
            getdomain(buf,q);
            return p+2;
        } else {
            printf("%.*s.",*p,p+1);
            p+=*p+1;
        }
    }
    return p+1;
}


unsigned char *getrr(const unsigned char *buf,const unsigned char *p,int num){
    int i;
    for(i=0; i<num; ++i) {
        p=getdomain(buf,p);
        DNS_RR *dnsrr=p;
        NTOHS(dnsrr->type);
        NTOHS(dnsrr->classes);
        NTOHS(dnsrr->TTL);
        NTOHS(dnsrr->rdlength);
        p+=sizeof(DNS_RR);
        printf(" ==> ");
        switch(dnsrr->type) {
        char ipaddr[INET6_ADDRSTRLEN];
        case 1:
            printf("%s",inet_ntop(PF_INET,p,ipaddr,sizeof(ipaddr)));
            break;
        case 2:
        case 5:
            getdomain(buf,p);
            break;
        case 28:
            printf("%s",inet_ntop(PF_INET6,p,ipaddr,sizeof(ipaddr)));
            break;
        }
        p+=dnsrr->rdlength;
        printf("\n");
    }
    return p;
}


int main ( int argc, char** argv ) {
    int      clifd,len = 0,i;
    struct   sockaddr_in  servaddr;
    unsigned char  buf[BUF_SIZE];
    unsigned char  *p;
    DNS_HDR  *dnshdr = ( DNS_HDR * ) buf;

    if ( ( clifd  =  socket ( AF_INET, SOCK_DGRAM, 0 ) )  <   0 ) {
        perror ( "create socket error" );
        return -1;
    }

    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(servaddr.sin_family,srv_ip,(void*)&(servaddr.sin_addr));
    servaddr.sin_port = htons ( SRV_PORT );


    memset ( buf, 0, BUF_SIZE );
    dnshdr->id = htons(1);
    dnshdr->flag = htons(RD);
    dnshdr->numq = htons ( 1 );

    p = buf + sizeof ( DNS_HDR ) + 1;
    strcpy ( p, argv[1] );

    i = 0;
    while ( p < ( buf + sizeof ( DNS_HDR ) + 1 + strlen ( argv[1] ) ) ) {
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
    dnsqer = ( DNS_QER * ) ( buf + sizeof ( DNS_HDR ) + 2 + strlen ( argv[1] ) );
    dnsqer->classes = htons(1);
    dnsqer->type = htons(28);


    len = sendto ( clifd, buf, sizeof ( DNS_HDR ) + sizeof ( DNS_QER ) + strlen ( argv[1] ) + 2, 0, ( struct sockaddr * ) &servaddr, sizeof ( servaddr ) );
    i = sizeof ( struct sockaddr_in );
    len = recvfrom ( clifd, buf, BUF_SIZE, 0, ( struct sockaddr * ) &servaddr, &i );

    if ( len < 0 ) {
        printf ( "recv error\n" );
        return -1;
    }

    NTOHS(dnshdr->id);
    NTOHS(dnshdr->flag);
    NTOHS(dnshdr->numq);
    NTOHS(dnshdr->numa);
    NTOHS(dnshdr->numa1);
    NTOHS(dnshdr->numa2);
    if ( dnshdr->id != 1 || dnshdr->flag & QR == 0 || dnshdr->flag & RCODE_MASK != 0 ) {
        printf ( "ack error\n" );
        return -1;
    }
    p = buf+sizeof(DNS_HDR);
    for(i=0; i<dnshdr->numq; ++i) {
        p=getdomain(buf,p);
        printf(" recodes:\n");
        p+=sizeof(DNS_QER);
    }
    p=getrr(buf,p,dnshdr->numa);
    p=getrr(buf,p,dnshdr->numa1);
    p=getrr(buf,p,dnshdr->numa2);
 
    
    close ( clifd );
    return 0;
}
