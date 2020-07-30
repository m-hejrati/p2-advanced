
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet_body);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet_body + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

    static int count = 1; // packet counter
    printf("\nPacket %d:\n", count);
    count++;

	printf("     Length: %d bytes\n", ntohs(ip->ip_len));

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		default:
			printf("   Protocol: another\n");
			return;
	}


	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet_body + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet_body + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	printf("    Payload: %d bytes\n", size_payload);

    return;
}

 char* select_device(){

    pcap_if_t *alldevsp , *device;
    char devs[100][100];
	char *errbuf;
	int count = 1;
	int n;

	//First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
     
    //Print the available devices
    printf("\n\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
     
    //Ask user which device to sniff
    printf("\nEnter the number of device you want to sniff : ");
    scanf("%d" , &n);
	char* dev = devs[n];
    return dev;

 }

int main() {
    char *device; //= "ens33"; // device to sniff on
    pcap_t *handle; // session handle
    char error_buffer[PCAP_ERRBUF_SIZE]; // error string
    char filter_exp[] = "tcp port 80"; // filter expression
    struct bpf_program filter; // compiled filter
    bpf_u_int32 subnet_mask, ip;
	struct pcap_pkthdr header; //header that pcap gives us
	const u_char *packet; // actual packet
	int num_packets; // number of packets to capture 

	// select device
	device = select_device();

    printf("\nEnter number of packets you want to capture: ");
    scanf("%d" , &num_packets);
    
	// open device in promiscuous mode
    handle = pcap_open_live(device, BUFSIZ, 1, 0, error_buffer);
    if (handle == NULL) {
        printf("Couldn't open device %s - %s\n", device, error_buffer);
        return 1;
    }

	// compile the filter expression
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 1;
    }
	// apply the compiled filter
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 1;
    }

	// print capture info
	printf("\nStart sniffing...\n");
	printf("Device: %s\n", device);
	printf("Number of packets: %d\n\n", num_packets);

    // start sniffing
	pcap_loop(handle, num_packets, packet_handler, NULL);

	// cleanup 
	pcap_freecode(&filter);
	pcap_close(handle);

    return 0;
}