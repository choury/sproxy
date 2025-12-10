#include "rproxy_listener.h"
#include "guest_tproxy.h"
#include "misc/util.h"

struct ListenerState {
    size_t id = 0;
    Destination bind;
    std::string rproxy;
    Destination target;
    std::shared_ptr<Tproxy_server> server;
};

std::map<size_t, ListenerState> g_listeners;
size_t g_next_listener_id = 1;

//bind: <destination>
//target: [rproxy]@<destination>
bool add_rproxy_listener(const std::string& bind_spec, const std::string& target_spec) {
    ListenerState state{};
    if(parseBind(bind_spec.c_str(), &state.bind)) {
        return false;
    }
    if(state.bind.protocol[0] == '\0') {
        strcpy(state.bind.protocol, "tcp");
    }
    auto pos = target_spec.find('@');
    if(pos == std::string::npos) {
        return false;
    }
    state.rproxy = target_spec.substr(0, pos);
    if(parseBind(target_spec.substr(pos+1).c_str(), &state.target)) {
        return false;
    }
    if(state.target.hostname[0] == '\0' ||
       strcmp(state.target.hostname, "[::]") == 0 ||
       strcmp(state.target.hostname, "0.0.0.0") == 0)
    {
        return false;
    }
    if(state.target.protocol[0] == '\0') {
        strcpy(state.target.protocol, state.bind.protocol);
    }

    listenOption ops = {
        .disable_defer_accepct = true,
        .enable_ip_transparent = false,
    };
    int fd;
    if(strcmp(state.bind.protocol, "tcp") == 0) {
        fd = ListenTcpD(&state.bind, &ops);
    } else if(strcmp(state.bind.protocol, "udp") == 0) {
        fd = ListenUdpD(&state.bind, &ops);
    } else if(strcmp(state.bind.protocol, "unix") == 0) {
        fd = ListenUnixD(&state.bind, &ops);
    } else {
        return false;
    }
    if(fd < 0) {
        LOGE("rproxy failed to bind %s\n", dumpDest(&state.bind));
        return false;
    }
    state.server = std::make_shared<Tproxy_server>(fd, state.rproxy, state.target);
    state.id = g_next_listener_id++;
    g_listeners[state.id] = state;
    LOG("rproxy listen #%zd %s -> %s@%s\n",
        state.id, dumpDest(state.bind).c_str(), state.rproxy.c_str(), dumpDest(state.target).c_str());
    return true;
}

bool remove_rproxy_listener(uint64_t id) {
    auto it = g_listeners.find(id);
    if(it == g_listeners.end()) {
        return false;
    }
    LOG("rproxy close #%zd %s@%s\n",
        it->second.id, it->second.rproxy.c_str(), dumpDest(it->second.target).c_str());
    g_listeners.erase(it);
    return true;
}

std::vector<std::string> list_rproxy_listeners() {
    std::vector<std::string> list;
    for(const auto& [id, state] : g_listeners) {
        list.emplace_back(
            std::to_string(id) + " " +
            dumpDest(state.bind).c_str() + " -> " +
            state.rproxy + "@" +
            dumpDest(state.target).c_str()
        );
    }
    return list;
}
