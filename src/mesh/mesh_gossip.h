#ifndef MESH_GOSSIP_H__
#define MESH_GOSSIP_H__

#include <cstdint>
#include <string>
#include <vector>

//节点表条目（docs/mesh.md 5.1）。HMAC 是成员级认证：任何持密钥成员都能构造
//合法条目，防的是非成员投毒；防成员投毒靠 addrs 主机名必须等于节点名（见
//valid_entry，配合 TLS 域名钉扎把投毒降级为纯 DoS）
struct MeshEntry {
    std::string name;
    std::vector<std::string> addrs;
    std::vector<std::string> caps; //目前仅 "exit"
    std::string via;               //reach-via，NAT 节点用，Phase 4
    int64_t seen = 0;              //条目签名的 Unix 秒
    std::string sig;               //base64(HMAC-SHA256(mesh_secret, canonical))

    bool has_cap(const char* c) const;
};

namespace MeshGossip {

//结构校验：addrs 中每个 URL 的主机名必须等于节点名
bool valid_entry(const MeshEntry& e);
//新鲜度：|now - seen| ≤ window，同时拒旧条目回滚与未来时间戳钉死
bool fresh_entry(const MeshEntry& e, int64_t now, int64_t window = 300);
void sign_entry(MeshEntry& e, const char* secret);
bool verify_entry(const MeshEntry& e, const char* secret);

std::string entry_to_json(const MeshEntry& e);
std::string entries_to_json(const std::vector<MeshEntry>& es);
//解析 /mesh/nodes 响应（数组）或 /mesh/announce 请求体（单对象）
std::vector<MeshEntry> parse_entries(const std::string& body);

}

#endif
