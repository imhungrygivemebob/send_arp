#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>

void callback(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	unsigned short ether_type;
	int chcnt = 0;
	int length = pkthdr->len;
	struct ether_header* target_header;
	struct ether_arp* target_arp;
	struct in_addr tmp_addr;
	target_header = (struct ether_header*)packet;
	packet += sizeof(struct ether_arp);

	ether_type =  ntohs(target_header->ether_type);
	if(ether_type == ETHERTYPE_ARP)
	{
		target_arp = (struct ether_arp*)packet;
		printf("ARP PACKET\n");
		printf("Sender mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", target_arp->arp_sha[0], target_arp->arp_sha[1], target_arp->arp_sha[2], target_arp->arp_sha[3], target_arp->arp_sha[4], target_arp->arp_sha[5]);
		memcpy(&tmp_addr, &target_arp->arp_spa, sizeof(tmp_addr));
		printf("Sender IP : %s\n", inet_ntoa(tmp_addr));
		printf("Target mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", target_arp->arp_tha[0], target_arp->arp_tha[1], target_arp->arp_tha[2], target_arp->arp_tha[3], target_arp->arp_tha[4], target_arp->arp_tha[5]);
	}

	printf("\n\n");
}

int main(int argc, char* argv[])
{
	int fd;
	const char* target_ip_string = argv[1];
	struct ifreq ifr;
	char* iface = "eth0";
	unsigned char* mac;
	struct sockaddr_in* source_ip_addr;
	struct ether_header header;
	header.ether_type = htons(ETH_P_ARP);
	memset(header.ether_dhost, 0xff, sizeof(header.ether_dhost));

	struct ether_arp req;
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = ETHER_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op = htons(ARPOP_REQUEST);
	memset(&req.arp_tha, 0, sizeof(req.arp_tha));


	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;

	printf("MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
	
	printf("%s\n", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	printf("%s\n", inet_ntoa(source_ip_addr->sin_addr));

	struct in_addr target_ip_addr = {0};
	if(!inet_aton(target_ip_string, &target_ip_addr))
	{
		printf("invalid IP Address\n");
		return -1;
	}

	printf("%s\n", inet_ntoa(target_ip_addr));

	memcpy(&req.arp_tpa, &target_ip_addr.s_addr, sizeof(req.arp_tpa));

	memcpy(&req.arp_spa,  &source_ip_addr->sin_addr.s_addr, sizeof(req.arp_spa));

	memcpy(header.ether_shost, mac, sizeof(header.ether_shost));

	memcpy(&req.arp_sha, mac, sizeof(req.arp_sha));

	unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];

	memcpy(frame, &header, sizeof(struct ether_header));
	memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp));

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';
	pcap_t* pcap = pcap_open_live(iface, 96, 0, 0, pcap_errbuf);
	if(pcap_errbuf[0] != '\0')
	{
		printf("%s\n", pcap_errbuf);
	}
	if(!pcap)
	{
		return -1;
	}
	int inj = pcap_inject(pcap, frame, sizeof(frame));
	if(inj == -1)
	{
		pcap_perror(pcap, 0);
		pcap_close(pcap);
		return -1;
	}

	printf("%d\n", inj);
	pcap_close(pcap);	

	char* net;
	char* mask;

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	int ret;
	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;
	struct ether_header* eptr;
	const u_char* packet;

	struct bpf_program fp;

	ret = pcap_lookupnet(iface, &netp, &maskp, pcap_errbuf);
	if(ret == -1)
	{
		printf("%s\n", pcap_errbuf);
		return -1;
	}

	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("NET : %s\n", net);
	
	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("MSK : %s\n", mask);
	printf("=================================\n");

	pcap = pcap_open_live(iface, 96, 0, 0, pcap_errbuf);
	if(pcap == NULL)
	{
		printf("%s\n", pcap_errbuf);
		return -1;
	}

	if(pcap_compile(pcap, &fp, "port 80", 0, netp) == -1)
	{
		printf("compile error\n");
		return -1;
	}

	if(pcap_setfilter(pcap, &fp) == -1)
	{
		printf("setfilter error\n");
		return -1;
	}

	pcap_loop(pcap, -1, callback, NULL);
		
	return 0;
}
