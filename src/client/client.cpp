#include "prot/rpc.h"
#include "common/version.h"

#include <iostream>
#include <readline/readline.h>
#include <readline/history.h>
#include <getopt.h>
#include <unistd.h>

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

static struct option long_options[] = {
        {"help",          no_argument,       nullptr, 'h'},
        {"version",       no_argument,       nullptr, 'v'},
        {"socket",        required_argument, nullptr, 's'},
        {nullptr,         0,         nullptr,  0 },
};

void usage(const char* name) {
    printf("Usage of %s:\n"
           "-s/--socket string\n"
           "      The socket of sproxy server listening\n", name);
}

static void show_version(const char* name){
    printf("%s version: %s, build time: %s\n", name, VERSION, BUILDTIME);
}

/* A structure which contains information on the commands this program
   can understand. */
typedef void (*cmdfunc_t)(SproxyClient* c, const std::vector<std::string>&);
typedef char* (*generatorfunc_t) (const char* text, int state);
typedef struct {
    const char *name;			/* User printable name of the function. */
    cmdfunc_t func;		/* Function to call to do the job. */
    const char *doc;			/* Documentation for this function.  */
    generatorfunc_t gen;
} COMMAND;


/*
 * COMPLETION_SKELETON: a sketleton to facilitate the implementation of a custom completion
 *  generator for GNU readline.
 * @arg array       : a char* array with possible commands
 * @arg nb_elements : the length of @param(array)
 */
#define COMPLETION_SKELETON(array, nb_elements) \
    do { \
        static int len; \
        static int index; \
        \
        if (!state) { \
            index = 0; \
            len = strlen(text); \
        } \
        \
        while (index < nb_elements) \
            if (strncmp(array[index], text, len) == 0) \
                return strdup(array[index++]); \
            else \
                index++; \
        \
        return NULL; \
        } \
    while (0)


static void com_adds(SproxyClient* c, const std::vector<std::string>& args){
    if (args.size() < 3) {
        std::cout << "adds require 2 params at least" << std::endl;
        return;
    }
    std::string ext;
    if (args.size() > 3) {
        ext = args[3];
    }
    auto r = c->AddStrategy(args[2], args[1], ext);
    if (!r.get_future().get()) {
        std::cout << "failed" << std::endl;
    }
}


static char *generator_adds(const char* text, int state){
    static const char *strategies[] = {"local", "proxy", "rewrite", "direct", "forward", "block"};
    static const int nb_elements = (sizeof(strategies)/sizeof(strategies[0]));
    COMPLETION_SKELETON(strategies, nb_elements);
}


static void com_dels(SproxyClient* c, const std::vector<std::string>& args){
    if (args.size() < 2) {
        std::cout << "adds require 1 param at least" << std::endl;
        return;
    }
    auto r = c->DelStrategy(args[1]);
    if (!r.get_future().get()) {
        std::cout << "failed" << std::endl;
    }
}

static void com_test(SproxyClient* c, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "test require 1 param at least" << std::endl;
        return;
    }
    auto r = c->TestStrategy(args[1]);
    std::cout<<r.get_future().get()<<std::endl;
}

static void com_sites(SproxyClient* c, const std::vector<std::string>&) {
    auto r = c->ListStrategy();
    auto sites = r.get_future().get();
    for(const auto& item: sites){
        std::cout << item << std::endl;
    }
}

static void com_flush(SproxyClient* c, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "flush require 1 param at least" << std::endl;
        return;
    }
    switch(hash_run_time(args[1])){
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
        std::cout << "don't know how to flush "<<args[1]<<std::endl;
        break;
    }
}

static char *generator_flush(const char* text, int state){
    static const char *flush_cmds[] = {"dns", "cgi", "strategy"};
    static const int nb_elements = (sizeof(flush_cmds)/sizeof(flush_cmds[0]));
    COMPLETION_SKELETON(flush_cmds, nb_elements);
}

static void com_switch(SproxyClient* c, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "switch require 1 param at least" << std::endl;
        return;
    }
    auto r = c->SetServer(args[1]);
    if (!r.get_future().get()) {
        std::cout << "failed" << std::endl;
    }
}


static void com_server(SproxyClient* c, const std::vector<std::string>&) {
    auto r = c->GetServer();
    std::cout<<r.get_future().get()<<std::endl;
}

static void com_exit(SproxyClient*, const std::vector<std::string>&) {
    exit(0);
}

static void com_help(SproxyClient*, const std::vector<std::string>& args);
static char *command_generator (const char* text, int state);

COMMAND commands[] = {
        { "adds", com_adds, "<strategy> <host> [ext]\tAdd strategy for host", generator_adds},
        { "dels", com_dels, "<host>\tDelete strategy for host", nullptr},
        { "test", com_test, "<host>\tTest strategy for host", nullptr},
        { "sites", com_sites, "\tGet strategy lists", nullptr},
        { "flush", com_flush, "<cgi|dns|strategy>", generator_flush},
        { "switch", com_switch, "<proxy>\tSet proxy server", nullptr},
        { "server", com_server, "\tGet proxy server", nullptr},
        { "exit", com_exit, "\tQuit the program", nullptr},
        { "help", com_help, "\tDisplay this text", command_generator},
        {nullptr, nullptr, nullptr, nullptr},
};

static void com_help(SproxyClient*, const std::vector<std::string>& args){
    if(args.size() == 1){
        for(auto com: commands){
            if(com.name == nullptr) {
                break;
            }
            std::cout << com.name<<" "<<com.doc<<std::endl;
        }
    }
    if(args.size() > 1){
        for(auto com: commands){
            if(com.name == nullptr || args[1] != com.name) {
                continue;
            }
            std::cout << com.name<<" "<<com.doc<<std::endl;
            return;
        }
        std::cout <<"unknown command: "<<args[1]<<std::endl;
    }
}


/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */
static char *command_generator (const char* text, int state) {
    static size_t list_index, len;
    /* If this is a new word to complete, initialize now.  This includes
    saving the length of TEXT for efficiency, and initializing the index
    variable to 0. */
    if (state == 0) {
        list_index = 0;
        len = strlen(text);
    }

    const char *name;
    /* Return the next name which partially matches from the command list. */
    while ((name = commands[list_index].name)) {
        list_index++;

        if (strncmp (name, text, len) == 0)
            return strdup(name);
    }

    /* If no names matched, then return NULL. */
    return nullptr;
}

/* Attempt to complete on the contents of TEXT.  START and END bound the
   region of rl_line_buffer that contains the word to complete.  TEXT is
   the word to complete.  We can use the entire contents of rl_line_buffer
   in case we want to do some simple parsing.  Return the array of matches,
   or NULL if there aren't any. */
static char **sproxy_completion (const char* text, int start, int ) {
    /* If this word is at the start of the line, then it is a command
    to complete.  Otherwise it is the name of a file in the current
    directory. */
    if (start == 0)
        return rl_completion_matches(text, command_generator);

    // true iff user entered 'cmd text<TAB>'
    #define USR_ENTERED(cmd) \
        (start >= (int)strlen(cmd)+1 && (strncmp(rl_line_buffer+start-strlen(cmd)-1, \
            cmd, strlen(cmd)) == 0)) // +1 for space

    for(auto cmd: commands){
        if(cmd.gen == nullptr){
            continue;
        }
        if (USR_ENTERED(cmd.name)){
            return rl_completion_matches(text, cmd.gen);
        }
    }
    return nullptr;
}


int main(int argc, char** argv) {
    const char* sock = nullptr;
    for(int c = 0; c != EOF ; c = getopt_long(argc, argv, "s:hv", long_options, nullptr)){
        switch(c){
        case '?':
            usage(argv[0]);
            exit(1);
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'v':
            show_version(argv[0]);
            exit(0);
        case 's':
            sock = optarg;
            break;
        }
    }
    if(sock == nullptr){
        if(access("/var/run/sproxy.sock", R_OK|W_OK) == 0){
            sock = "/var/run/sproxy.sock";
        }
        if(access("/tmp/sproxy.sock", R_OK|W_OK) == 0){
            sock = "/tmp/sproxy.sock";
        }
        if(sock == nullptr){
            fprintf(stderr, "no socket file found, should use -s to set it\n");
            exit(2);
        }
    }
    printf("connect to socket: %s\n", sock);
    SproxyClient *c = new SproxyClient(sock);

    /* Allow conditional parsing of the ~/.inputrc file. */
    rl_readline_name = (char*)"sproxy";

    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = sproxy_completion;
    while(true) {
        char *input = readline("> ");
        if(!input){
            break;
        }
        auto tokens = split(input);
        if(tokens.empty()){
            free(input);
            continue;
        }
        add_history(input);
        free(input);
        try {
            bool executed = false;
            for(auto cmd: commands){
                if(cmd.name && tokens[0] == cmd.name){
                    cmd.func(c, tokens);
                    executed = true;
                    break;
                }
            }
            if(!executed){
                std::cout << "unknown command" << std::endl;
            }
        }catch(std::string& s){
            std::cerr <<"error: "<< s << std::endl;
        }
    }
    return 0;
}
