#include <string>
#include <iostream>
#include <sstream>
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
#include <netinet/in.h>
#include <arpa/inet.h>
#if __linux__
#include <sys/sendfile.h>
#endif

#define MAXLINE 4096
using namespace std;

int getline(int fd, string &line) {
    line.clear();
    int n;
    char buf;
    while ((n = read(fd, &buf, 1)) > 0) {
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

int read_http_head(int fd){
    string line;
    size_t len = INT_MAX;
    bool is_trunk = false;
    while(getline(fd, line) > 0){
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

int read_fixed_len(int fd, size_t len){
    char buf[MAXLINE];
    size_t nread = 0;
    while (len > 0) {
        int n = read(fd, buf, std::min((size_t)MAXLINE, len));
        if (n <= 0) {
            return n;
        }
        cout.write(buf, n);
        len -= n;
        nread += n;
        continue;
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


int main(int argc , char *argv[]) {
    string line;
    int sockfd = 0;
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

            sockfd = socket(AF_INET , SOCK_STREAM , 0);
            if (sockfd == -1){
                cerr<<"Fail to create a socket: "<<strerror(errno)<<endl;
                return -2;
            }
            struct sockaddr_in server;
            server.sin_addr.s_addr = inet_addr(addr.c_str());
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            if (connect(sockfd , (struct sockaddr *)&server , sizeof(server)) < 0){
                cerr<<"Fail to connect to <"<<addr<<":"<<port<<">: "<<strerror(errno)<<endl;
                return -2;
            }
        }else if(cmd == "reset"){
            struct linger sl;
            sl.l_onoff = 1;		/* non-zero value enables linger option in kernel */
            sl.l_linger = 0;	/* timeout interval in seconds */
            setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
            close(sockfd);
        }else if(cmd == "listen") {
            string prot;
            int port;
            ss >> prot >> port;
            if(ss.fail() || (prot != "tcp" && prot != "udp")){
                cerr << "listen udp/tcp <port>" << endl;
                return -1;
            }
            struct sockaddr_in sockaddr;
            memset(&sockaddr,0,sizeof(sockaddr));

            sockaddr.sin_family = AF_INET;
            sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
            sockaddr.sin_port = htons(port);

            if(prot == "tcp"){
                int fd = socket(AF_INET, SOCK_STREAM,0);
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
                sockfd = accept(fd, (struct sockaddr*)&sockaddr, &addrlen);
                if(sockfd <  0){
                    cerr<<"Fail to accept <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                close(fd);
            }else{
                sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                int flag = 1;
                if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
                    cerr<<"setsockopt SO_REUSEADDR: "<< strerror(errno)<<endl;
                    return -2;
                }

#ifdef SO_REUSEPORT
                if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
                    cerr<<"setsockopt SO_REUSEPORT: "<< strerror(errno)<<endl;
                    return -2;
                }
#endif
                if(::bind(sockfd,(struct sockaddr *)&sockaddr,sizeof(sockaddr)) < 0){
                    cerr<<"Fail to bind <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                char buf;
                socklen_t addrlen = sizeof(sockaddr);
                if(recvfrom(sockfd, &buf, 1, MSG_PEEK, (struct sockaddr *)&sockaddr, &addrlen) < 0){
                    cerr<<"Fail to recvfrom <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
                if(connect(sockfd, (struct sockaddr *)&sockaddr, addrlen) < 0){
                    cerr<<"Fail to connect <"<<prot<<":"<<port<<">: "<<strerror(errno)<<endl;
                    return -2;
                }
            }
        }else if(cmd == "sendfile") {
            string file;
            ss >> file;
            if (ss.fail()) {
                cerr << "sendfile <file>" << endl;
                return -1;
            }
            int fd = open(file.c_str(), O_RDONLY);
            if (fd == -1) {
                cerr << "Fail to open file " << file << ": " << strerror(errno) << endl;
                return -2;
            }
#ifdef __APPLE__
            int len = 0;
            // OSX does not support sendfile on UDP sockets
            char buff[1024];
            while ((len = read(fd, buff, sizeof(buff))) > 0) {
                if (write(sockfd, buff, len) < 0) {
                    cerr << "Fail to send file " << file << ": " << strerror(errno) << endl;
                    return -2;
                }
            }
            if (len < 0) {
                cerr << "Fail to read file " << file << ": " << strerror(errno) << endl;
                return -2;
            }
#endif
#ifdef __linux__
            off_t len = 0;
            if(sendfile(sockfd, fd, &len, UINT32_MAX) < 0){
                cerr << "Fail to send file "<<file<<": " << strerror(errno) << endl;
                return -2;
            }
#endif
            close(fd);
        }else if(cmd == "send"){
            string data = decode(line.substr(ss.tellg()));
            if(write(sockfd, data.c_str(), data.size()) < 0){
                cerr<<"Fail to send message: "<<strerror(errno)<<endl;
                return -2;
            }
        }else if(cmd == "read"){
            string size;
            ss >> size;
            if(ss.fail()){
                cerr << "read <size>/eof/head/http/line" << endl;
                return -1;
            }
            char buf[MAXLINE];
            if(size == "eof") {
                while (true) {
                    int n = read(sockfd, buf, MAXLINE);
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
                if (read_http_head(sockfd) < 0) {
                    cerr << "Fail to read http header from server: "<<strerror(errno) << endl;
                    return -2;
                }
            }else if (size == "http") {
                int len = read_http_head(sockfd);
                if(len < 0){
                    cerr << "Fail to read http header from server: "<< strerror(errno) << endl;
                    return -2;
                }
                if(len == 0){
                    string chunk;
                    while(getline(sockfd, chunk) > 0){
                        size_t chunk_len = strtol(chunk.c_str(), NULL, 16);
                        if(read_fixed_len(sockfd, chunk_len + 2) <= 0) {
                            cerr << "Fail to read chunk body from server: "<< strerror(errno) << endl;
                            return -2;
                        }
                        if(chunk_len == 0)
                            break;
                    }
                }else{
                    if(read_fixed_len(sockfd, len) <= 0) {
                        cerr << "Fail to read http body from server: "<< strerror(errno) << endl;
                        return -2;
                    }
                }
            } else if(size == "line") {
                string oneline;
                if (getline(sockfd, oneline) > 0) {
                    cout << oneline;
                } else {
                    cerr << "Fail to read line from server: " << strerror(errno) << endl;
                    return -2;
                }
            } else if(size == "packet") {
                int ret = 0;
                if((ret = read(sockfd, buf, MAXLINE)) < 0){
                    cerr << "Fail to read packet from server: " << strerror(errno) << endl;
                    return -2;
                }
                cout.write(buf, ret);
            } else {
                int nread = atoi(size.c_str());
                if (read_fixed_len(sockfd, nread) <= 0) {
                    cerr << "Fail to read from server: " << strerror(errno) << endl;
                    return -2;
                }
            }
        }else if(cmd == "shutdown") {
            if(shutdown(sockfd, SHUT_WR) == -1) {
                cerr << "Fail to shutdown: " << strerror(errno) << endl;
                return -2;
            }
        }else if(cmd == "close") {
            close(sockfd);
        }else if(cmd == "sleep") {
            int sec;
            ss >> sec;
            if (ss.fail()) {
                cout << "sleep <sec>" << endl;
                return -1;
            }
            sleep(sec);
        }else{
            cerr << "Unknown command: " << cmd << endl;
        }
    }
    (void)argc;
    (void)argv;
	return 0;
}
