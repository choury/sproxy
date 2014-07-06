#include <map>
#include <string>
#include <string.h>
#include <fstream>
#include <iostream>
#include <unordered_set>

#include "parse.h"
#include "net.h"

using namespace std;

static int loadedsite = 0;
static unordered_set<string> blocklist;

void loadblocksite()
{
    loadedsite = 1;
    blocklist.clear();
    ifstream blockfile("blocked.list");
    if (blockfile.good()) {
        while (!blockfile.eof()) {
            string site;
            blockfile >> site;
            blocklist.insert(site);
        }
        for (auto i : blocklist) {
            cout << i << endl;
        }
        blockfile.close();
    } else {
        cerr << "There is no blocked.list!" << endl;
    }
}


int checkblock(const char* host)
{
    if (!loadedsite) {
        loadblocksite();
    }
    const char *subhost = host;
    while (subhost) {
        if(subhost[0] == '.'){
            subhost++;
        }
        if (blocklist.find(subhost) != blocklist.end()) {
            return 1;
        }
        subhost = strpbrk(subhost, ".");
    }

    return 0;
}

void parse(char* header)
{
    map<string, string> hmap;
    strcpy(header, header);
    for (char* str = header; ; str = NULL) {
        char* p = strtok(str, CRLF);
        if (p == NULL)
            break;
        char* sp = strpbrk(p, ":");
        hmap[string(p, sp - p)] = string(sp + 1);
    }

    int p = 0;
    for (auto i : hmap) {
        int len;
        sprintf(header + p, "%s:%s" CRLF "%n", i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }
    sprintf(header + p, CRLF);

}
