#include "arp.hpp"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/udp.h>

#include <csignal>
#include <string>
#include <vector>

struct NFQData{
  struct LocalInfo local_info;
  std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs;
};

struct dnshdr {
  uint16_t id;        // identification number
  uint16_t flags;     // DNS flags
  uint16_t qd_count;  // number of question entries
  uint16_t ans_cnt;   // number of answer entries
  uint16_t authrr_cnt;// number of authority entries
  uint16_t addrr_cnt; // number of resource entries
};

struct __attribute__((packed, aligned(2))) resphdr {
  uint16_t name;
  uint16_t type;
  uint16_t cls; // class
  uint32_t ttl;
  uint16_t len;
};

#define ETH2_HEADER_LEN 14

void handle_sigint(int sig);
void setup_forwarding(const char *interface);

uint16_t calTCPChecksum(struct iphdr *iph, struct udphdr *udph, int resp_mv);
uint16_t calIPChecksum(struct iphdr *iph);
std::string parseDNSQuery(const unsigned char *packet, int dns_start, int &dns_name_length);
void sendDNSReply(char *data, int len, struct NFQData *info);
static int handleNFQPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void NFQHandler(struct LocalInfo local_info, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs);