#include "arp.hpp"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include <csignal>
#include <string>
#include <vector>

struct NFQData{
  struct LocalInfo local_info;
  std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs;
};

void handle_sigint(int sig);
void setup_forwarding(const char *interface);

void printUsernameAndPassword(uint8_t *payload, int payload_length);
static int handleNFQPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void NFQHandler(struct LocalInfo local_info, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs); 