#ifndef RPROXY_LISTENER_H__
#define RPROXY_LISTENER_H__

#include <stdint.h>

#include <string>
#include <vector>

bool add_rproxy_listener(const std::string& bind_spec, const std::string& target_spec);
bool remove_rproxy_listener(uint64_t id);
std::vector<std::string> list_rproxy_listeners();

#endif // RPROXY_LISTENER_H__
