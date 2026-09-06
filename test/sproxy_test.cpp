//sproxy_test：stdin脚本驱动的协议测试客户端。传输层为可组合的channel栈
//(channel.h)：connect建fd层，tlsconnect叠加TLS层，h2connect叠加h2 CONNECT
//流层，任意嵌套；send/read/shutdown/close等命令只操作栈顶，语义恒定。
//命令一览：
//  connect <addr> <port>        建TCP连接(fd层)
//  sendto <addr> <port> <str>   建UDP连接并首发一包(fd层)
//  listen tcp|udp <port>        监听并接受一个连接(fd层)
//  tlsconnect [sni] [ech|-] [alpn] 在栈顶channel上叠加TLS层(ech: grease/
//               base64 ECHConfigList；alpn: 逗号分隔，如h2,http/1.1)
//  h2connect <authority>        在栈顶channel上开h2 CONNECT流(host:port)，
//               等2xx后本连接变为流内字节管道
//  send <data>                  发送数据，支持\r \n \t \\ \xNN转义
//  sendfile <file>              发送整个文件
//  read eof|head|http|line|packet|<N> 读：到EOF/响应头/完整响应/一行/
//               一个包/固定字节数
//  shutdown                     写半关(fd=SHUT_WR，tls=close_notify，h2=END_STREAM)
//  close                        关闭并释放整个channel栈
//  reset                        SO_LINGER暴力关闭fd层(裸fd专用)
//  sleep <sec> / echo <str> / echgen <file> <public_name> / exit
#include "channel.h"
#include "tls_chan.h"
#include "h2_chan.h"

#include <string>
#include <iostream>
#include <sstream>
#include <memory>
#include <fstream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAXLINE 4096
using namespace std;

int getline(Channel& chan, string &line) {
    line.clear();
    int n;
    char buf;
    while ((n = chan.read(&buf, 1)) > 0) {
        line += buf;
        if (buf == '\n') {
            return line.size();
        }
    }
    return n;
}

bool istart_with(const string& s, const char* prefix) {
    for(size_t i = 0; i < strlen(prefix) && i < s.size(); i++) {
        if(tolower(s[i]) != tolower(prefix[i])) {
            return false;
        }
    }
    return true;
}

int read_http_head(Channel& chan){
    string line;
    size_t len = INT_MAX;
    bool is_trunk = false;
    while(getline(chan, line) > 0){
        cout.write(line.c_str(), line.size());
        if(istart_with(line, "Content-Length:")){
            const char* p = line.c_str() + strlen("Content-Length:");
            while(*p == ' ')
                p++;
            len =  atoi(p);
        }
        if(istart_with(line, "Transfer-Encoding:")){
            const char* p = line.c_str() + strlen("Transfer-Encoding:");
            while(*p == ' ')
                p++;
            if(strncasecmp(p, "chunked", 7) == 0)
                is_trunk = true;
        }
        if(line == "\r\n"){
            return is_trunk ? 0: len;
        }
    }
    return -1;
}

int read_fixed_len(Channel& chan, size_t len){
    char buf[MAXLINE];
    size_t nread = 0;
    while (len > 0) {
        int n = chan.read(buf, std::min((size_t)MAXLINE, len));
        if (n <= 0) {
            return n;
        }
        cout.write(buf, n);
        len -= n;
        nread += n;
   }
    return nread;
}

string decode(const string& str){
    string ret;
    size_t i = 0;
    while((i < str.size()) && (str[i] == ' ' || str[i] == '\t'))
        i++;
    for(; i < str.size(); i++){
        if(str[i] != '\\'){
            ret += str[i];
        }else if(i + 1 >= str.size()) {
            break;
        }else if(i + 2 < str.size() && str[i + 1] == 'x'){
            //\xNN十六进制转义，供脚本发送二进制字节
            int hexval = 0;
            bool ok = true;
            for(int k = 2; k <= 3; k++) {
                char c = str[i + k];
                int v = (c >= '0' && c <= '9') ? c - '0' :
                        (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                        (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if(v < 0) {
                    ok = false;
                    break;
                }
                hexval = hexval * 16 + v;
            }
            if(ok) {
                ret += (char)hexval;
                i += 3;
            }else{
                ret += str[i];
            }
        }else {
            i++;
            switch(str[i]){
            case 'r':
                ret += '\r';
                break;
            case 'n':
                ret += '\n';
                break;
            case 't':
                ret += '\t';
                break;
            case '\\':
                ret += '\\';
                break;
            default:
                ret += str[i];
                break;
            }
        }
    }
    return ret;
}

void SetSocketUnblock(int fd){
    if(fd < 0){
        return;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0){
        fprintf(stderr, "fcntl error %d: %s\n", fd, strerror(errno));
    }
    int ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if(ret < 0){
        fprintf(stderr, "fcntl error %d: %s\n", fd, strerror(errno));
    }
}


//解析host:port为socket地址，支持域名/IPv4/IPv6字面量，失败返回-1
static int resolve_addr(const string& host, int port, int socktype,
                        sockaddr_storage* ss, socklen_t* alen) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo* result = nullptr;
    if(getaddrinfo(host.c_str(), portstr, &hints, &result) != 0 || result == nullptr) {
        return -1;
    }
    memcpy(ss, result->ai_addr, result->ai_addrlen);
    *alen = result->ai_addrlen;
    freeaddrinfo(result);
    return 0;
}

//关闭旧栈并换上新fd层
static void replace_channel(unique_ptr<Channel>& chan, int fd) {
    if(chan) {
        chan->close();
    }
    chan = make_unique<RawChannel>(fd);
}

int main(int argc , char *argv[]) {
    //对端关闭后再写(如隧道FIN后的SSL_write)按错误处理，不让SIGPIPE杀进程
    signal(SIGPIPE, SIG_IGN);
    string line;
    unique_ptr<Channel> chan;
    while(getline(cin, line)){
        stringstream ss(line);
        string cmd;
        ss >> cmd;
        if(cmd[0] == '#' || cmd.empty()){
            continue;
        }if(cmd == "exit") {
            break;
        }else if(cmd == "echo"){
            cout << decode(line.substr(ss.tellg())) << endl;
        }else if(cmd == "connect"){
            string addr;
            int port;
            ss >> addr >> port;
            if(ss.fail()){
                cerr << "connect <addr> <port>" << endl;
                return -1;
            }

            struct sockaddr_storage server;
            socklen_t alen = 0;
            if(resolve_addr(addr, port, SOCK_STREAM, &server, &alen) < 0){
                cerr<<"Fail to resolve <"<<addr<<":"<<port<<">"<<endl;
                return -2;
            }
            int fd = socket(server.ss_family , SOCK_STREAM , 0);
            if (fd == -1){
                cerr<<"Fail to create a socket: "<<strerror(errno)<<endl;
                return -2;
            }
            if (connect(fd , (struct sockaddr *)&server , alen) < 0){
                cerr<<"Fail to connect to <"<<addr<<":"<<port<<">: "<<strerror(errno)<<endl;
                return -2;
            }
            replace_channel(chan, fd);
        }else if(cmd == "sendto") {
            string addr,str;
            int port;
            ss>>addr>>port>>str;
            if(ss.fail()){
                cerr << "sendto <addr> <port> <str>" << endl;
                return -1;
            }
            struct sockaddr_storage address;
            socklen_t alen = 0;
            if(resolve_addr(addr, port, SOCK_DGRAM, &address, &alen) < 0){
                cerr<<"Fail to resolve <"<<addr<<":"<<port<<">"<<endl;
                return -2;
            }
            int fd = socket(address.ss_family , SOCK_DGRAM , 0);
            if (fd == -1){
                cerr<<"Fail to create a socket: "<<strerror(errno)<<endl;
                return -2;
            }
            if(sendto(fd, str.c_str(), str.length(), 0, (sockaddr*)&address, alen) < 0){
                cerr<<"Fail to sendto <"<<addr<<":"<<port<<">: "<<strerror(errno)<<endl;
                return -2;
            }
            replace_channel(chan, fd);
        }else if(cmd == "reset"){
            int fd = chan ? chan->fd() : -1;
            if(fd < 0){
                cerr << "reset: raw connection required" << endl;
                return -1;
            }
            struct linger sl;
            sl.l_onoff = 1;		/* non-zero value enables linger option in kernel */
            sl.l_linger = 0;	/* timeout interval in seconds */
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
            chan.reset();
            close(fd);
        }else if(cmd == "listen") {
            string prot;
            int port;
            ss >> prot >> port;
            if(ss.fail() || (prot != "tcp" && prot != "udp")){
                cerr << "listen udp/tcp <port>" << endl;
                return -1;
            }
            struct sockaddr_in6 sockaddr;
            memset(&sockaddr, 0, sizeof(sockaddr));

            sockaddr.sin6_family = AF_INET6;
            sockaddr.sin6_addr = in6addr_any;
            sockaddr.sin6_port = htons(port);

            if(prot == "tcp"){
                int fd = socket(AF_INET6, SOCK_STREAM, 0);
                int flag = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
                    cerr<<"setsockopt SO_REUSEADDR: "<< strerror(errno)<<endl;
                    return -2;
                }

#ifdef SO_REUSEPORT
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
                    cerr<<"setsockopt SO_REUSEPORT: "<< strerror(errno)<<endl;
                    return -2;
                }
#endif
                if(::bind(fd,(struct sockaddr *)&sockaddr,sizeof(sockaddr)) < 0){
                    cerr<<"Fail to bind <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                if(listen(fd,1024) < 0){
                    cerr<<"Fail to listen <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                socklen_t addrlen = sizeof(sockaddr);
                int cfd = accept(fd, (struct sockaddr*)&sockaddr, &addrlen);
                if(cfd <  0){
                    cerr<<"Fail to accept <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                close(fd);
                replace_channel(chan, cfd);
            }else{
                int fd = socket(AF_INET6, SOCK_DGRAM, 0);
                int flag = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
                    cerr<<"setsockopt SO_REUSEADDR: "<< strerror(errno)<<endl;
                    return -2;
                }

#ifdef SO_REUSEPORT
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
                    cerr<<"setsockopt SO_REUSEPORT: "<< strerror(errno)<<endl;
                    return -2;
                }
#endif
                if(::bind(fd,(struct sockaddr *)&sockaddr,sizeof(sockaddr)) < 0){
                    cerr<<"Fail to bind <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                char buf;
                socklen_t addrlen = sizeof(sockaddr);
                if(recvfrom(fd, &buf, 1, MSG_PEEK, (struct sockaddr *)&sockaddr, &addrlen) < 0){
                    cerr<<"Fail to recvfrom <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                if(connect(fd, (struct sockaddr *)&sockaddr, addrlen) < 0){
                    cerr<<"Fail to connect <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                replace_channel(chan, fd);
            }
        }else if(cmd == "sendfile") {
            string file;
            ss >> file;
            if (ss.fail() || !chan) {
                cerr << "sendfile <file>" << endl;
                return -1;
            }
            int fd = open(file.c_str(), O_RDONLY);
            if (fd == -1) {
                cerr << "Fail to open file " << file << ": " << strerror(errno) << endl;
                return -2;
            }
            off_t len = 0;
            char buff[16 * 1024];
            while ((len = read(fd, buff, sizeof(buff))) > 0) {
                if (chan->write(buff, len) < 0) {
                    cerr << "Fail to send file " << file << ": " << strerror(errno) << endl;
                    return -2;
                }
            }
            if (len < 0) {
                cerr << "Fail to read file " << file << ": " << strerror(errno) << endl;
                return -2;
            }
            close(fd);
        }else if(cmd == "send"){
            string data = decode(line.substr(ss.tellg()));
            if(!chan || chan->write(data.data(), data.size()) < 0){
                cerr<<"Fail to send message: "<<strerror(errno)<<endl;
                return -2;
            }
        }else if(cmd == "read"){
            string size;
            ss >> size;
            if(ss.fail() || !chan){
                cerr << "read <size>/eof/head/http/line/packet" << endl;
                return -1;
            }
            char buf[MAXLINE];
            if(size == "eof") {
                while (true) {
                    int n = chan->read(buf, MAXLINE);
                    if (n == 0) {
                        break;
                    }
                    if (n > 0) {
                        cout.write(buf, n);
                        continue;
                    }
                    cerr << "Fail to read from server: " << strerror(errno) << endl;
                    return -2;
                }
            } else if (size == "head") {
                if (read_http_head(*chan) < 0) {
                    cerr << "Fail to read http header from server: "<<strerror(errno) << endl;
                    return -2;
                }
            }else if (size == "http") {
                int len = read_http_head(*chan);
                if(len < 0){
                    cerr << "Fail to read http header from server: "<< strerror(errno) << endl;
                    return -2;
                }
                if(len == 0){
                    string chunk;
                    while(getline(*chan, chunk) > 0){
                        size_t chunk_len = strtol(chunk.c_str(), nullptr, 16);
                        if(read_fixed_len(*chan, chunk_len + 2) <= 0) {
                            cerr << "Fail to read chunk body from server: "<<strerror(errno) << endl;
                            return -2;
                        }
                        if(chunk_len == 0)
                            break;
                    }
                }else{
                    if(read_fixed_len(*chan, len) <= 0) {
                        cerr << "Fail to read http body from server: "<<strerror(errno) << endl;
                        return -2;
                    }
                }
            } else if(size == "line") {
                string oneline;
                if (getline(*chan, oneline) > 0) {
                    cout << oneline;
                } else {
                    cerr << "Fail to read line from server: " << strerror(errno) << endl;
                    return -2;
                }
            } else if(size == "packet") {
                int ret = 0;
                if((ret = chan->read(buf, MAXLINE)) < 0){
                    cerr << "Fail to read packet from server: " << strerror(errno) << endl;
                    return -2;
                }
                cout.write(buf, ret);
            } else {
                int nread = atoi(size.c_str());
                if (nread == 0) {
                    cerr << "Fail to parse bytes: "<<size<<endl;
                    return -2;
                }
                if (read_fixed_len(*chan, nread) <= 0) {
                    cerr << "Fail to read from server: " << strerror(errno) << endl;
                    return -2;
                }
            }
        }else if(cmd == "shutdown") {
            if(chan) {
                chan->shutdown_wr();
            }
        }else if(cmd == "close") {
            if(chan) {
                chan->close();
                chan.reset();
            }
        }else if(cmd == "sleep") {
            int sec;
            ss >> sec;
            if (ss.fail()) {
                cout << "sleep <sec>" << endl;
                return -1;
            }
            sleep(sec);
        }else if(cmd == "echgen") {
            string file, public_name;
            ss >> file >> public_name;
            if(ss.fail()) {
                cerr << "echgen <file> <public_name>" << endl;
                return -1;
            }
            int ret = ech_gen(file, public_name);
            if(ret) return ret;
        }else if(cmd == "tlsconnect") {
            string sni, ech, alpn;
            ss >> sni >> ech >> alpn; //均可省略
            if(!chan) {
                cerr << "tlsconnect: no connection, run connect first" << endl;
                return -2;
            }
            auto tls = make_unique<TlsChannel>(std::move(chan), sni, ech, alpn);
            if(!tls->ok) {
                return -2;
            }
            chan = std::move(tls);
        }else if(cmd == "h2connect") {
            string authority;
            ss >> authority;
            if(ss.fail()) {
                cerr << "h2connect <authority>" << endl;
                return -1;
            }
            if(!chan) {
                cerr << "h2connect: no connection, run connect first" << endl;
                return -2;
            }
            auto h2 = make_unique<H2Channel>(std::move(chan), authority);
            if(!h2->ok) {
                return -2;
            }
            chan = std::move(h2);
        }else{
            cerr << "Unknown command: " << cmd << endl;
        }
    }
    if(chan) {
        chan->close();
    }
    (void)argc;
    (void)argv;
	return 0;
}
