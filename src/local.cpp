#include "local.hpp"


void getDefaultGateway(const char *interface, struct sockaddr_in &gateway_addr) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp == nullptr) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }

    char line[100], iface[10];
    unsigned long dest, gateway;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s\t%lX\t%lX", iface, &dest, &gateway) == 3) {
            if (strcmp(iface, interface) == 0 && dest == 0) {  // Default gateway
                gateway_addr.sin_family = AF_INET;
                gateway_addr.sin_addr.s_addr = gateway;
                break;
            }
        }
    }
    // Print gateway IP address.
    // char gateway_ip[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &gateway_addr.sin_addr, gateway_ip, INET_ADDRSTRLEN);
    // printf("Gateway IP address: %s\n", gateway_ip);

    fclose(fp);
}

void getSourceIP(const char *interface, struct sockaddr_in &ipv4) {
    int sd;
    struct ifreq ifr;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its IPv4 address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl() failed to get source IP address");
        return;
    }

    // Copy source IP address.
    memcpy(&ipv4, &ifr.ifr_addr, sizeof(struct sockaddr_in));

    close(sd);
}

void getMACAddress(const char *interface, std::array<uint8_t, 6> &src_mac) {
    int sd;
    struct ifreq ifr;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address");
        close(sd);
        return;
    }

    // Copy source MAC address.
    std::copy(ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + 6, src_mac.begin());

    close(sd);
}

void getMask(const char *interface, struct sockaddr_in &netmask) {
    struct ifreq ifr;
    int sd;

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its netmask.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl() failed to get netmask");
        exit(EXIT_FAILURE);
    }

    // Copy netmask.
    memcpy(&netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));

    close(sd);
}
