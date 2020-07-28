#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

/*  
    2020.07.26 (Sun)
    Author : Jin Gunseung (comalmot)
    required : apt install libnet-dev 
*/

int main(int argc, char* argv[]) {
    pcap_t* handle;

    if (argc != 2) {
        printf("Usage : %s <interface>\n", argv[0]);
    }
    
    char* dev = argv[1];
	
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
    	printf("pcap_open_live() error!\n");
    }

    while(1) {
    	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 0) continue;
	if (res == -1 || res == -2) {
		printf("pcap_next_ex!!!!");
		break;
	}

	printf("%u bytes captured\n", header->caplen);
    }
    struct libnet_ethernet_hdr A;
    struct libnet_ipv4_hdr B;
    struct libnet_tcp_hdr C;

    pcap_close(handle);

    
    return 0;
}
