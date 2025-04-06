#include <stdlib.h>
#include <stdio.h>
#include <pcap.h> // libpcap 라이브러리를 사용
#include <arpa/inet.h>
#include <netinet/ether.h> //이더넷 주소 변환 함수를 사용(ether_ntoa)

/* Ethernet header */
struct ethheader {
    __u_char  ether_dhost[6];    // destination host address (목적지 MAC 주소)
    __u_char  ether_shost[6];    // source host address (출발지 MAC 주소)
    __u_short ether_type;        // IP,ARP, etc.. (상위 프로토콜 유형)
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    __u_short tcp_sport;               // source port 
    __u_short tcp_dport;               // destination port 
    __u_int   tcp_seq;                 // sequence number 
    __u_int   tcp_ack;                 // acknowledgement number 
    __u_char  tcp_offx2;               // data offset, rsvd 
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    __u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    __u_short tcp_win;                 // window 
    __u_short tcp_sum;                 // checksum 
    __u_short tcp_urp;                 // urgent pointer 
};

// 패킷 캡쳐 함수 
void packet_capture(__u_char *args, const struct pcap_pkthdr *header,
    const __u_char *packet)
{
struct ethheader *eth = (struct ethheader *)packet;
struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader)+ ip->iph_ihl * 4);

// Ethernet 출력
printf("(Ethernet)Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
printf("(Ethernet)Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

// IP 출력
printf("(IP)Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
printf("(IP)Destination IP: %s\n", inet_ntoa(ip->iph_destip));

// TCP 출력 
printf("(TCP)Source Port: %d\n", ntohs(tcp->tcp_sport));
printf("(TCP)Destination Port: %d\n", ntohs(tcp->tcp_dport));

printf("\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Step 1: Open live pcap session on NIC with name enp0s3
    // 실시간 패킷 캡쳐 
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    // pcap_compile(handle, &fp, filter_exp, 0, net);
    // if (pcap_setfilter(handle, &fp) !=0) {
    // pcap_perror(handle, "Error:");
    // exit(EXIT_FAILURE);
    // }

    // Step 3: Capture packets
    // 캡처한 패킷마다 packet_capture 함수 호출 
    pcap_loop(handle, -1, packet_capture, NULL);

    pcap_close(handle);   //Close the handle 
    return 0;
}