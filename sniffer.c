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

#include<signal.h>
#include<unistd.h>

struct device {
	
	char name [20];
	char ip [16];
};

struct IP {

	char src [16];
	char dst [16];
};

int packet_number = 0;

struct session_info {
	int No;
	char type [4];
	char src_IP[16];
	char dst_IP[16];
	long scr_port;
	long dst_port;
	int num_req;
	int num_rsp;
	long len;
	int status;
};

struct session_info session[500];
int z = 0;


void save_session(char type[], struct IP ip, int src_port, int dst_port, int Size, int fin){

	int flag = 1;

	for (int i = 0; i < z; i++){
		
		if (strcmp(session[i].type, type) == 0)

			if ( (strcmp(session[i].src_IP, ip.src) == 0) && (strcmp(session[i].dst_IP, ip.dst) == 0) && (session[i].scr_port == src_port) && (session[i].dst_port == dst_port) ){
				
				session[i].num_req ++;
				session[i].len += Size;
				flag = 0;
				session[i].status = fin;
				break;

			} else if ( (strcmp(session[i].src_IP, ip.dst) == 0) && (strcmp(session[i].dst_IP, ip.src) == 0) && (session[i].scr_port == dst_port) && (session[i].dst_port == src_port) ){

				session[i].num_rsp ++;
				session[i].len += Size;
				flag = 0;
				session[i].status = fin;
				break;

			}
	}

	if (flag){
		
		session[z].No = z+1;
		strcpy(session[z].type, type);
		strcpy(session[z].src_IP, ip.src);
		strcpy(session[z].dst_IP, ip.dst);
		session[z].scr_port = src_port;
		session[z].dst_port = dst_port;
		session[z].num_req = 1;
		session[z].num_rsp = 0;
		session[z].len = Size;
		session[z].status = fin;
		z++;
	}

}

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
void print_ip_header(int Size, struct IP ip) {
	
    syslog(LOG_INFO, "Packet size: %d bytes\n", Size);
	syslog(LOG_INFO, "     Src IP: %s\n", ip.src);
	syslog(LOG_INFO, "     Dst IP: %s\n", ip.dst);
}

// separate useful part of ip header
struct IP Processing_ip_header(const u_char * Buffer, int Size) {

	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	// get source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
    // get destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

    struct IP ip;
	strcpy(ip.src, inet_ntoa(source.sin_addr));  
	strcpy(ip.dst, inet_ntoa(dest.sin_addr));

	return ip;
}

// print useful data of tcp header
void print_tcp_header(const u_char * Buffer, int Size, struct tcphdr *tcph) {

    syslog(LOG_INFO, "   Src port: %d\n", ntohs(tcph->source));
	syslog(LOG_INFO, "   Dst port: %d\n", ntohs(tcph->dest));
}

// print useful data of udp header
void print_udp_header(const u_char *Buffer , int Size, struct udphdr *udph){
	
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

	// get ip from function
	struct IP ip = Processing_ip_header(Buffer, Size);

	syslog(LOG_INFO, " ");
	packet_number ++;
	syslog(LOG_INFO, "     number: %d", packet_number);
	syslog(LOG_INFO, "   Protocol: TCP\n");
	
	print_ip_header(Size, ip);
    print_tcp_header(Buffer, Size, tcph);

	syslog(LOG_INFO, "    payload: %s", printable_payload);
	
	printf("%d) TCP packet logged\n", packet_number);

	save_session("tcp", ip, ntohs(tcph->source), ntohs(tcph->dest), Size, (int)tcph->fin);
}

// separate useful part of udp packet
void Processing_udp_packet(const u_char * Buffer, int Size){

	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	// get printable part of payload
	char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);

	// get ip from function
	struct IP ip = Processing_ip_header(Buffer, Size);

	syslog(LOG_INFO, " ");
	packet_number ++;
	syslog(LOG_INFO, "     number: %d", packet_number);
	syslog(LOG_INFO, "   Protocol: UDP\n");
	
	print_ip_header(Size, ip);
	print_udp_header(Buffer , Size, udph);
	syslog(LOG_INFO, "    payload: %s", printable_payload);

	printf("%d) UDP packet logged\n", packet_number);

	save_session("udp", ip, ntohs(udph->source), ntohs(udph->dest), Size, 0);
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
struct device select_device(){

    pcap_if_t *alldevsp , *device;
    //char devs[100][100];
	struct device devices [20];
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
			// save device name
            strcpy(devices[count].name , device->name);

			// save device ip
			for(pcap_addr_t *a=device->addresses; a!=NULL; a=a->next) {
            	if(a->addr->sa_family == AF_INET) 
            		strcpy(devices[count].ip , inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
        	}

        }
        count++;
    }
     
    //ask user to select a device to sniff
    printf("\nEnter the number of device you want to sniff : ");
    scanf("%d" , &n);

	// copy and return selected device
	struct device selected_device;
	strcpy(selected_device.name, devices[n].name);
	strcpy(selected_device.ip, devices[n].ip);

    return selected_device;

 }

// define handle global, to use it in sig_handler function
pcap_t *handle;

// run this function after 30 second of capturing
void sig_handler(int signum){

	pcap_breakloop(handle);

	if (z != 0){

		printf("%d packet in %d session recorded in last 30 seconds \n", packet_number, z);
		syslog(LOG_INFO, " ");
		syslog(LOG_INFO, "%d session recorded in last 30 seconds \n", z);

		for(int i = 0; i < z; i++){

			syslog(LOG_INFO, " ");
			syslog(LOG_INFO, "Session No: %d", i+1);
			syslog(LOG_INFO, "  Protocol: %s", session[i].type);
			syslog(LOG_INFO, "    Src IP: %s", session[i].src_IP);
			syslog(LOG_INFO, "    Dst IP: %s", session[i].dst_IP);
			syslog(LOG_INFO, "  Src port: %ld", session[i].scr_port);
			syslog(LOG_INFO, "  Dst port: %ld", session[i].dst_port);
			syslog(LOG_INFO, "      Sent: %d", session[i].num_req);
			syslog(LOG_INFO, "  Received: %d", session[i].num_rsp);
			syslog(LOG_INFO, "Total Size: %ld", session[i].len);
			if (strcmp(session[i].type, "tcp") == 0)
				if(session[i].status)
					syslog(LOG_INFO, "    Status: close");
				else 
					syslog(LOG_INFO, "    Status: open");
		}
	
		z = 0;
		packet_number = 0;		

	}else{
		syslog(LOG_INFO, " ");
		syslog(LOG_INFO, "No packet captured in last 30 seconds \n");
		printf("No packet captured in last 30 seconds \n");	
	}
}

// the main function
int main() {

    struct device device; // device to sniff on
    //pcap_t *handle; // session handle
    char error_buffer[PCAP_ERRBUF_SIZE]; // error string
	// filter expression (second part of the following expression means to filter packet with body)
    //char filter_exp[] = "((tcp port 8765) or (udp port 53))and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	char filter_exp[] = "";
	struct bpf_program filter; // compiled filter
    bpf_u_int32 raw_mask; // subnet mask
	bpf_u_int32 ip; // ip
    struct in_addr addr;
	char *mask; // dot notation of the network mask
	struct pcap_pkthdr header; //header that pcap gives us
	const u_char *packet; // actual packet
	int num_packets; // number of packets to capture 

	// open logging machine
	openlog("p2-advanced | sniffer", LOG_PID, LOG_USER);

	// select device
	device = select_device();

	// ask pcap for the network address and mask of the device
    if( pcap_lookupnet(device.name, &ip, &raw_mask, error_buffer) == -1){

        printf("Couldn't read device %s information - %s\n", device.name, error_buffer);
		syslog(LOG_ERR, "Couldn't read device %s information - %s\n", device.name, error_buffer);
    }
	
	// get the subnet mask in a human readable form
    addr.s_addr = raw_mask;
    mask = inet_ntoa(addr);

	// print device information
	printf("\nDevice info\n");
	printf("Name: %s\n", device.name);
	printf("IP: %s\n", device.ip);
	printf("MASK: %s\n",mask);
	
    printf("\nEnter number of packets you want to capture: ");
    scanf("%d" , &num_packets);
    
	// open device in promiscuous mode
    handle = pcap_open_live(device.name, BUFSIZ, 1, 0, error_buffer);
    if (handle == NULL) {
        printf("Couldn't open device %s - %s\n", device.name, error_buffer);
		syslog(LOG_ERR, "Couldn't open device %s - %s\n", device.name, error_buffer);
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
	printf("\nStart sniffing...\n\n");
	printf("Number of packets: %d\n\n", num_packets);
    syslog(LOG_INFO, "Start sniffing on device: %s and %d packets", device.name, num_packets);

	while (1) {
			
		signal(SIGALRM, sig_handler);
		alarm(30);

		// start sniffing
		pcap_loop(handle, num_packets, packet_handler, NULL);

	}

	// cleanup 
	pcap_freecode(&filter);
	pcap_close(handle);


    closelog();
    return 0;
}
