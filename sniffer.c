#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <syslog.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<netinet/udp.h>   // for udp header
#include<netinet/tcp.h>   // for tcp header
#include<netinet/ip.h>    // for ip header

#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

struct sockaddr_in source,dest;

// find and save prinatble part of payload
char* find_printable_payload(const u_char *payload, int len){

	const u_char *ch = payload;
	char printable[10000] = "";
	int j = 0;
	
	// find printable character and save them into a new string.
	for(int i = 0; i < len; i++) {

		if (isprint(*ch)){
			printable[j] = *ch;
			j++;

		} else if ((*ch) == '\n' || (*ch) == ' '){
            printable[j] = *ch;
			j++;
        }

		ch++;
	}
	
	char* tmp = printable;
	return tmp;
}

// print useful data of ip header
void print_ip_header(const u_char * Buffer, int Size) {

	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	// get source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
    // get destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
    syslog(LOG_INFO, "Packet size: %d bytes\n", Size);
	syslog(LOG_INFO, "     Src IP: %s\n", inet_ntoa(source.sin_addr));
	syslog(LOG_INFO, "     Dst IP: %s\n",  inet_ntoa(dest.sin_addr));
}

// print useful data of tcp header
void print_tcp_packet(const u_char * Buffer, int Size, struct tcphdr *tcph) {

	syslog(LOG_INFO, "   Protocol: TCP - HTTP\n");
	
	print_ip_header(Buffer,Size);
	
    syslog(LOG_INFO, "   Src port: %d\n", ntohs(tcph->source));
	syslog(LOG_INFO, "   Dst port: %d\n", ntohs(tcph->dest));
}

// print useful data of udp header
void print_udp_packet(const u_char *Buffer , int Size, struct udphdr *udph){

	syslog(LOG_INFO, "   Protocol: UDP\n");
	
	print_ip_header(Buffer,Size);
	
    syslog(LOG_INFO, "   Src port: %d\n", ntohs(udph->source));
	syslog(LOG_INFO, "   Dst port: %d\n", ntohs(udph->dest));
	
}

// separate useful part of tcp packet
void Processing_tcp_packet(const u_char * Buffer, int Size) {
    
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    // get printable part of payload
    char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);

    // check if payload contains word "HTTP" or not
	if (strstr(printable_payload, "HTTP") != NULL){

	syslog(LOG_INFO, " ");
        print_tcp_packet(Buffer, Size, tcph);
	    syslog(LOG_INFO, "    payload: %s", printable_payload);
	printf("TCP packet logged\n");
    }
}

// separate useful part of udp packet
void Processing_udp_packet(const u_char * Buffer, int Size){

	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	syslog(LOG_INFO, " ");
    print_udp_packet(Buffer , Size, udph);
    
    // get printable part of payload
    char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);
	syslog(LOG_INFO, "    payload: %s", printable_payload);

	printf("UDP packet logged\n");
}

// the major part of the program that gets a packet and extract important data of it
void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
	int size = packet_header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(packet_body + sizeof(struct ethhdr));

	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 6:  //TCP Protocol
			Processing_tcp_packet(packet_body , size);
			break;
		
		case 17: //UDP Protocol
			Processing_udp_packet(packet_body , size);
			break;
		
		default: //Other Protocol
			return;
	}
}

// show all available device and choose one of them to sniff
char* select_device(){

    pcap_if_t *alldevsp , *device;
    char devs[100][100];
	char *errbuf;
	int count = 1;
	int n;

	//get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
		syslog(LOG_ERR, "Error finding devices : %s" , errbuf);
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
     
    //ask user to select a device to sniff
    printf("\nEnter the number of device you want to sniff : ");
    scanf("%d" , &n);

	char* dev = devs[n];
    return dev;

 }

// the main function
int main() {

    char *device; // device to sniff on
    pcap_t *handle; // session handle
    char error_buffer[PCAP_ERRBUF_SIZE]; // error string
	// filter expression (second part of the following expression means to filter packet with body)
    //char filter_exp[] = "tcp port 8765 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
    char filter_exp[] = "((tcp port 8765) or (udp port 53))and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	struct bpf_program filter; // compiled filter
    bpf_u_int32 subnet_mask, ip;
	struct pcap_pkthdr header; //header that pcap gives us
	const u_char *packet; // actual packet
	int num_packets; // number of packets to capture 

	// open logging machine
	openlog("p2-advanced | sniffer", LOG_PID, LOG_USER);

	// select device
	device = select_device();

    printf("\nEnter number of packets you want to capture: ");
    scanf("%d" , &num_packets);
    
	// open device in promiscuous mode
    handle = pcap_open_live(device, BUFSIZ, 1, 0, error_buffer);
    if (handle == NULL) {
        printf("Couldn't open device %s - %s\n", device, error_buffer);
		syslog(LOG_ERR, "Couldn't open device %s - %s\n", device, error_buffer);
        return 1;
    }

	// compile the filter expression
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
		syslog(LOG_ERR, "Bad filter - %s\n", pcap_geterr(handle));
        return 1;
    }
	// apply the compiled filter
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
		syslog(LOG_ERR, "Error setting filter - %s\n", pcap_geterr(handle));
        return 1;
    }

	// print capture info
	printf("\nStart sniffing...\n");
	printf("Device: %s\n", device);
	printf("Number of packets: %d\n\n", num_packets);
    syslog(LOG_INFO, "Start sniffing on device: %s and %d packets", device, num_packets);

    // start sniffing
	pcap_loop(handle, num_packets, packet_handler, NULL);

	// cleanup 
	pcap_freecode(&filter);
	pcap_close(handle);

    closelog();
    return 0;
}