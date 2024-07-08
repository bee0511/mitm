#include <linux/if_packet.h>
#include <net/if.h>      // for struct ifreq
#include <netinet/in.h>  // for struct sockaddr_in
#include <sys/ioctl.h>   // for ioctl()
#include <sys/socket.h>  // for socket(), AF_INET, SOCK_RAW, IPPROTO_RAW
#include <sys/types.h>   // for uint8_t
#include <unistd.h>      // for close()

#include <array>    // for std::array
#include <cstdio>   // for fopen(), fgets(), perror()
#include <cstdlib>  // for exit()
#include <cstring>  // for strcmp(), memset(), memcpy()

// Define a struct for local info
struct LocalInfo {
    std::array<uint8_t, 6> src_mac;
    struct sockaddr_in src_ip;
    struct sockaddr_in netmask;
    struct sockaddr_in gateway_ip;
    struct sockaddr_ll device;
};

void getMACAddress(const char *interface, std::array<uint8_t, 6> &src_mac);
void getMask(const char *interface, struct sockaddr_in &netmask);
void getSourceIP(const char *interface, struct sockaddr_in &ipv4);
void getDefaultGateway(const char *interface, struct sockaddr_in &gateway_addr);
