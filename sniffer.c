#include <stdio.h>
#include <pcap.h>

// print differnet parts of packet
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    static int count = 1; // packet counter
    printf("Packet %d:\n", count);
    count++;
    printf("Packet length %d\n", packet_header.len);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    print_packet_info(packet_body, *packet_header);
    return;
}

int main(int argc, char **argv) {
    char *device = "any"; // device to sniff on
    pcap_t *handle; // session handle
    char error_buffer[PCAP_ERRBUF_SIZE]; // error string
    struct bpf_program filter; // compiled filter
    char filter_exp[] = "tcp port 80"; // filter expression
    bpf_u_int32 subnet_mask, ip;
	struct pcap_pkthdr header; //header that pcap gives us
	const u_char *packet; // actual packet

    // open the session in promiscuous mode and 10 seconds capturing
    handle = pcap_open_live(device, BUFSIZ, 1, 10000, error_buffer);
    if (handle == NULL) {
        printf("Couldn't open device %s - %s\n", device, error_buffer);
        return 1;
    }

    // compile and apply the filter
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 1;
    }

    // start sniffing 10 packets 
	pcap_loop(handle, 10, packet_handler, NULL);

    return 0;
}