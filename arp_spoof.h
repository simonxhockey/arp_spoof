#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/netdevice.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#define ETHERTYPE_ARP 0x0806
#define ETHERYPE_IP 0x0800

struct ethernet_header {
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};

struct arp_header {
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;
	u_int8_t arp_sha[6];
	u_int8_t arp_spa[4];
	u_int8_t arp_tha[6];
	u_int8_t arp_tpa[4];
};

/* arp packet structure */
struct make_arp {
	struct ethernet_header eth_hdr;
	struct arp_header arp_hdr;
};

/*
	list for sender and receiver
	make one list per one pair(session)
*/
struct objective_list {
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t receiver_mac[6];
	u_int8_t receiver_ip[4];
};

void usage();
void get_my_dev(u_int8_t *ether, u_int8_t *ip, char *dev);
void send_arp_rep(pcap_t *handle, u_int8_t *ip, struct objective_list *list, u_int8_t *my_mac);
void send_arp_req(pcap_t *handle, u_int8_t *ip, struct objective_list *list, u_int8_t *my_mac, u_int8_t *my_ip,int type);


