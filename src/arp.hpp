#include "local.hpp"

#include <linux/if_arp.h>
#include <netinet/ip_icmp.h>

#include <algorithm>
#include <map>
#include <thread>

#define ETH_HDRLEN 14  // Ethernet header length
#define ARP_HDRLEN 28  // ARP header length

// Define a struct for ARP header
struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    std::array<uint8_t, 6> sender_mac;
    std::array<uint8_t, 4> sender_ip;
    std::array<uint8_t, 6> target_mac;
    std::array<uint8_t, 4> target_ip;
};

void sendARPRequest(int sd, struct LocalInfo local_info);
void receiveARPReply(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendSpoofedARPReply(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void parseARPReply(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
