#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

#pragma pack(push, 1)

struct my_packet{
	struct libnet_ethernet_hdr eth_header;
	struct libnet_ipv4_hdr ip_header;
	struct libnet_tcp_hdr tcp_header;
}__attribute__((packed));

/*  
    2020.07.26 (Sun)
    Author : Jin Gunseung (comalmot)
    required : apt install libnet-dev 
*/

void ret_mac(uint8_t mac[]) {
	
	for(int i = 0; i < 6; i++) {
	    printf("%02X", mac[i]);    
		
	    if(i != 5) {
	    	printf(":");
	    }
	}

	printf("\n");
}

void ethhdr_info(const u_char* eth) {
	struct libnet_ethernet_hdr* eth_hdr;
        eth_hdr	= (struct libnet_ethernet_hdr *)eth;

	printf("DEST MAC : "); 
	ret_mac(eth_hdr->ether_dhost);
	printf("SOURCE MAC : ");
	ret_mac(eth_hdr->ether_shost);

	
	//printf("PROTOCOL : %d\n", ntohs(eth_hdr->ether_type));
}

void iphdr_info(const u_char* eth) {
	struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)eth;
	//printf("IP VERSION : %d\n", ip_hdr->ip_v);
	//printf("IP HDR_LEN : %d\n", ip_hdr->ip_hl);
	//printf("IP TOS     : %d\n", ip_hdr->ip_tos);
	//printf("IP TOTAL_LEN : %d\n", ip_hdr->ip_len);
	//printf("TTL : %d\n", ip_hdr->ip_ttl);
	//printf("PROTOCOL : %d\n", ip_hdr->ip_p);
	printf("SRC IP : %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("DST IP : %s\n", inet_ntoa(ip_hdr->ip_dst));
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage : %s <interface>\n", argv[0]);
    }
    
    char* dev = argv[1];
	
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
    	fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
	return -1;
    }

    while(1) {
    	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 0) continue;
	if (res == -1 || res == -2) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		break;
	}	
        printf("Header info\n");
	ethhdr_info(packet);
	packet += sizeof(struct libnet_ethernet_hdr);
	iphdr_info(packet);
	printf("%u bytes captured\n", header->caplen);
    }
    struct libnet_ethernet_hdr A;
    struct libnet_ipv4_hdr B;
    struct libnet_tcp_hdr C;

    pcap_close(handle);

    
    return 0;
}