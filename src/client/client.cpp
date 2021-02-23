#include "prot/rpc.h"

#include <iostream>
#include <readline/readline.h>
#include <readline/history.h>

#define SKIP_CHAR(str)        ((*str)++)
static std::string gettoken(const char** line){
    while (isspace((unsigned char)(**line))){SKIP_CHAR(line);}
    const char* start = nullptr;
    switch(**line){
    case '\'':
        SKIP_CHAR(line);
        start = *line;
        while(**line && **line != '\''){SKIP_CHAR(line);}
        if(**line) {
            SKIP_CHAR(line);
            return std::string(start, *line - start - 1);
        }
        return std::string(start, *line - start);
    case '\"':
        SKIP_CHAR(line);
        start = *line;
        while(**line && **line != '\"'){SKIP_CHAR(line);}
        if(**line){
            SKIP_CHAR(line);
            return std::string(start, *line - start - 1);
        }
        return std::string(start, *line - start);
    default:
        start = *line;
        while(**line && !isspace((unsigned char)(**line))){SKIP_CHAR(line);}
        return std::string(start, *line - start);
    }
}

static std::vector<std::string> split(const char* line){
    std::vector<std::string> tokens;
    while(*line){
        tokens.emplace_back(gettoken(&line));
    }
    return tokens;
}

using hash_t = size_t;
constexpr hash_t prime = 0x100000001B3ull;
constexpr hash_t basis = 0xCBF29CE484222325ull;
static hash_t hash_run_time(const std::string& str) {
    hash_t ret = basis;
    for(auto c : str){
        ret ^= c;
        ret *= prime;
    }
    return ret;
}

constexpr hash_t hash_compile_time(const char* str, hash_t last_value = basis) {
    return *str ? hash_compile_time(str + 1, (*str ^ last_value) * prime) : last_value;
}

constexpr hash_t operator "" _hash(const char* p, size_t) {
    return hash_compile_time(p);
}

int main() {
    SproxyClient *c = new SproxyClient("/tmp/sproxy.sock");
    while(true) {
        char *input = readline("> ");
        if(!input){
            break;
        }
        auto tokens = split(input);
        add_history(input);
        free(input);
        try {
            switch (hash_run_time(tokens[0])) {
            case "adds"_hash: {
                if (tokens.size() < 3) {
                    std::cout << "adds require 2 params at least" << std::endl;
                    break;
                }
                std::string ext = "";
                if (tokens.size() > 3) {
                    ext = tokens[3];
                }
                auto r = c->AddStrategy(tokens[1], tokens[2], ext);
                if (!r.get_future().get()) {
                    std::cout << "failed" << std::endl;
                }
                break;
            }
            case "dels"_hash:{
                if (tokens.size() < 2) {
                    std::cout << "adds require 1 param at least" << std::endl;
                    break;
                }
                auto r = c->DelStrategy(tokens[1]);
                if (!r.get_future().get()) {
                    std::cout << "failed" << std::endl;
                }
                break;
            }
            case "test"_hash:{
                if (tokens.size() < 2) {
                    std::cout << "test require 1 param at least" << std::endl;
                    break;
                }
                auto r = c->TestStrategy(tokens[1]);
                std::cout<<r.get_future().get()<<std::endl;
                break;
            }
            case "sites"_hash:{
                auto r = c->ListStrategy();
                auto sites = r.get_future().get();
                for(const auto& item: sites){
                    std::cout << item << std::endl;
                }
                break;
            }
            case "flush"_hash:{
                if (tokens.size() < 2) {
                    std::cout << "flush require 1 param at least" << std::endl;
                    break;
                }
                switch(hash_run_time(tokens[1])){
                case "cgi"_hash:
                    c->FlushCgi().get_future().get();
                    break;
                case "dns"_hash:
                    c->FlushDns().get_future().get();
                    break;
                case "strategy"_hash:
                    c->FlushStrategy().get_future().get();
                    break;
                default:
                    std::cout << "don't know how to flush "<<tokens[1]<<std::endl;
                    break;
                }
                break;
            }
            case "switch"_hash:{
                if (tokens.size() < 2) {
                    std::cout << "switch require 1 param at least" << std::endl;
                    break;
                }
                auto r = c->SetServer(tokens[1]);
                if (!r.get_future().get()) {
                    std::cout << "failed" << std::endl;
                }
                break;
            }
            case "server"_hash:{
                auto r = c->GetServer();
                std::cout<<r.get_future().get()<<std::endl;
                break;
            }
            case "exit"_hash:
                exit(0);
            default:
                std::cout << "unknown command" << std::endl;
                break;
            }
        }catch(std::string& s){
            std::cerr <<"error: "<< s << std::endl;
        }
    }
    return 0;
}
