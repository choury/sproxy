#include "mesh_gossip.h"

#include <json.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

bool MeshEntry::has_cap(const char* c) const {
    for(auto& cap : caps) {
        if(cap == c) {
            return true;
        }
    }
    return false;
}

namespace MeshGossip {

//提取 URL 的主机名（scheme://host[:port]/...），仅用于条目结构校验
static bool url_host(const std::string& url, std::string& host) {
    size_t pos = url.find("://");
    if(pos == std::string::npos) {
        return false;
    }
    pos += 3;
    size_t end = url.find_first_of("/?#", pos);
    std::string authority = url.substr(pos, end == std::string::npos ? end : end - pos);
    //无 IPv6 中括号时剥离端口
    size_t colon = authority.rfind(':');
    if(colon != std::string::npos && authority.find(']') == std::string::npos) {
        authority.resize(colon);
    }
    if(authority.empty()) {
        return false;
    }
    host = authority;
    return true;
}

//签名的规范化串，字节格式钉死（顺序也是被签名内容的一部分）
static std::string canonical(const MeshEntry& e) {
    std::string str;
    str += e.name;
    str += '\n';
    for(size_t i = 0; i < e.addrs.size(); i++) {
        if(i) str += '\n';
        str += e.addrs[i];
    }
    str += '\n';
    for(size_t i = 0; i < e.caps.size(); i++) {
        if(i) str += ',';
        str += e.caps[i];
    }
    str += '\n';
    str += e.via;
    str += '\n';
    str += std::to_string(e.seen);
    return str;
}

static std::string hmac_sha256(const char* secret, const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret),
         (const unsigned char*)data.data(), data.size(), hash, &hash_len);
    char encoded[EVP_MAX_MD_SIZE * 2];
    EVP_EncodeBlock((unsigned char*)encoded, hash, (int)hash_len);
    return std::string(encoded, strlen(encoded));
}

bool valid_entry(const MeshEntry& e) {
    if(e.name.empty() || strchr(e.name.c_str(), '/') || strchr(e.name.c_str(), '+')) {
        return false;
    }
    //规范化串以 \n 与 , 分隔，name/via 只允许无歧义字符集（via 允许空）
    auto safe_token = [](const std::string& s) {
        for(unsigned char c : s) {
            if(!isalnum(c) && c != '.' && c != '_' && c != '-') {
                return false;
            }
        }
        return true;
    };
    if(!safe_token(e.name) || !safe_token(e.via)) {
        return false;
    }
    for(auto& addr : e.addrs) {
        std::string host;
        if(!url_host(addr, host) || host != e.name) {
            return false;
        }
    }
    return true;
}

bool fresh_entry(const MeshEntry& e, int64_t now, int64_t window) {
    return e.seen <= now + window && e.seen >= now - window;
}

void sign_entry(MeshEntry& e, const char* secret) {
    e.sig = hmac_sha256(secret, canonical(e));
}

bool verify_entry(const MeshEntry& e, const char* secret) {
    std::string expect = hmac_sha256(secret, canonical(e));
    return !e.sig.empty() && e.sig.size() == expect.size()
           && CRYPTO_memcmp(e.sig.data(), expect.data(), e.sig.size()) == 0;
}

static json_object* entry_to_json_obj(const MeshEntry& e) {
    json_object* jentry = json_object_new_object();
    json_object_object_add(jentry, "name", json_object_new_string(e.name.c_str()));
    json_object* jaddrs = json_object_new_array();
    for(auto& addr : e.addrs) {
        json_object_array_add(jaddrs, json_object_new_string(addr.c_str()));
    }
    json_object_object_add(jentry, "addrs", jaddrs);
    json_object* jcaps = json_object_new_array();
    for(auto& cap : e.caps) {
        json_object_array_add(jcaps, json_object_new_string(cap.c_str()));
    }
    json_object_object_add(jentry, "caps", jcaps);
    json_object_object_add(jentry, "via", json_object_new_string(e.via.c_str()));
    json_object_object_add(jentry, "seen", json_object_new_int64(e.seen));
    json_object_object_add(jentry, "sig", json_object_new_string(e.sig.c_str()));
    return jentry;
}

std::string entry_to_json(const MeshEntry& e) {
    json_object* jentry = entry_to_json_obj(e);
    std::string body = json_object_to_json_string(jentry);
    json_object_put(jentry);
    return body;
}

std::string entries_to_json(const std::vector<MeshEntry>& es) {
    json_object* jarr = json_object_new_array();
    for(auto& e : es) {
        json_object_array_add(jarr, entry_to_json_obj(e));
    }
    std::string body = json_object_to_json_string(jarr);
    json_object_put(jarr);
    return body;
}

static bool parse_entry(json_object* jentry, MeshEntry& e) {
    if(json_object_get_type(jentry) != json_type_object) {
        return false;
    }
    json_object* jname = json_object_object_get(jentry, "name");
    json_object* jaddrs = json_object_object_get(jentry, "addrs");
    json_object* jcaps = json_object_object_get(jentry, "caps");
    json_object* jvia = json_object_object_get(jentry, "via");
    json_object* jseen = json_object_object_get(jentry, "seen");
    json_object* jsig = json_object_object_get(jentry, "sig");
    if(!jname || !jaddrs || !jseen || !jsig
       || json_object_get_type(jname) != json_type_string
       || json_object_get_type(jaddrs) != json_type_array
       || json_object_get_type(jseen) != json_type_int) {
        return false;
    }
    e = MeshEntry{};
    e.name = json_object_get_string(jname);
    for(size_t i = 0; i < json_object_array_length(jaddrs); i++) {
        json_object* jaddr = json_object_array_get_idx(jaddrs, i);
        if(json_object_get_type(jaddr) != json_type_string) {
            return false;
        }
        e.addrs.push_back(json_object_get_string(jaddr));
    }
    if(jcaps && json_object_get_type(jcaps) == json_type_array) {
        for(size_t i = 0; i < json_object_array_length(jcaps); i++) {
            json_object* jcap = json_object_array_get_idx(jcaps, i);
            if(json_object_get_type(jcap) != json_type_string) {
                return false;
            }
            e.caps.push_back(json_object_get_string(jcap));
        }
    }
    if(jvia && json_object_get_type(jvia) == json_type_string) {
        e.via = json_object_get_string(jvia);
    }
    e.seen = json_object_get_int64(jseen);
    if(jsig && json_object_get_type(jsig) == json_type_string) {
        e.sig = json_object_get_string(jsig);
    }
    return true;
}

std::vector<MeshEntry> parse_entries(const std::string& body) {
    return parse_payload(body).entries;
}

static json_object* link_report_to_json_obj(const LinkReport& r) {
    json_object* jrep = json_object_new_object();
    json_object_object_add(jrep, "name", json_object_new_string(r.name.c_str()));
    json_object_object_add(jrep, "ts", json_object_new_int64(r.ts));
    json_object* jlinks = json_object_new_array();
    for(auto& [peer, rtt] : r.links) {
        json_object* jlink = json_object_new_object();
        json_object_object_add(jlink, "peer", json_object_new_string(peer.c_str()));
        json_object_object_add(jlink, "rtt", json_object_new_double(rtt));
        json_object_array_add(jlinks, jlink);
    }
    json_object_object_add(jrep, "links", jlinks);
    return jrep;
}

std::string link_report_json(const LinkReport& r) {
    json_object* jrep = link_report_to_json_obj(r);
    std::string body = json_object_to_json_string(jrep);
    json_object_put(jrep);
    return body;
}

static bool parse_link_report(json_object* jrep, LinkReport& r) {
    if(json_object_get_type(jrep) != json_type_object) {
        return false;
    }
    json_object* jname = json_object_object_get(jrep, "name");
    json_object* jts = json_object_object_get(jrep, "ts");
    json_object* jlinks = json_object_object_get(jrep, "links");
    if(!jname || json_object_get_type(jname) != json_type_string
       || !jts || json_object_get_type(jts) != json_type_int
       || !jlinks || json_object_get_type(jlinks) != json_type_array) {
        return false;
    }
    r = LinkReport{};
    r.name = json_object_get_string(jname);
    r.ts = json_object_get_int64(jts);
    for(size_t i = 0; i < json_object_array_length(jlinks); i++) {
        json_object* jlink = json_object_array_get_idx(jlinks, i);
        json_object* jpeer = json_object_object_get(jlink, "peer");
        json_object* jrtt = json_object_object_get(jlink, "rtt");
        if(json_object_get_type(jlink) != json_type_object
           || !jpeer || json_object_get_type(jpeer) != json_type_string
           || !jrtt || json_object_get_type(jrtt) != json_type_double) {
            continue; //单条坏链路不否定整份上报
        }
        r.links[json_object_get_string(jpeer)] = json_object_get_double(jrtt);
    }
    return true;
}

GossipPayload parse_payload(const std::string& body) {
    GossipPayload p;
    json_object* jroot = json_tokener_parse(body.c_str());
    if(!jroot) {
        return p;
    }
    if(json_object_get_type(jroot) == json_type_array) {
        for(size_t i = 0; i < json_object_array_length(jroot); i++) {
            MeshEntry e;
            if(parse_entry(json_object_array_get_idx(jroot, i), e)) {
                p.entries.push_back(e);
            }
        }
        json_object_put(jroot);
        return p;
    }
    if(json_object_get_type(jroot) == json_type_object) {
        json_object* jnodes = json_object_object_get(jroot, "nodes");
        if(!jnodes && !json_object_object_get(jroot, "metrics")) {
            //无载荷键的对象按单条目处理（announce 请求体形态）
            MeshEntry e;
            if(parse_entry(jroot, e)) {
                p.entries.push_back(e);
            }
            json_object_put(jroot);
            return p;
        }
        if(jnodes && json_object_get_type(jnodes) == json_type_array) {
            for(size_t i = 0; i < json_object_array_length(jnodes); i++) {
                MeshEntry e;
                if(parse_entry(json_object_array_get_idx(jnodes, i), e)) {
                    p.entries.push_back(e);
                }
            }
        }
        json_object* jmetrics = json_object_object_get(jroot, "metrics");
        if(jmetrics && json_object_get_type(jmetrics) == json_type_array) {
            for(size_t i = 0; i < json_object_array_length(jmetrics); i++) {
                LinkReport r;
                if(parse_link_report(json_object_array_get_idx(jmetrics, i), r)) {
                    p.metrics.push_back(r);
                }
            }
        }
    }
    json_object_put(jroot);
    return p;
}

std::string build_payload(const GossipPayload& p) {
    json_object* jroot = json_object_new_object();
    json_object* jnodes = json_object_new_array();
    for(auto& e : p.entries) {
        json_object_array_add(jnodes, entry_to_json_obj(e));
    }
    json_object_object_add(jroot, "nodes", jnodes);
    json_object* jmetrics = json_object_new_array();
    for(auto& r : p.metrics) {
        json_object_array_add(jmetrics, link_report_to_json_obj(r));
    }
    json_object_object_add(jroot, "metrics", jmetrics);
    std::string body = json_object_to_json_string(jroot);
    json_object_put(jroot);
    return body;
}

}
