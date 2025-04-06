#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define ETHERTYPE_IP 0x0800

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    } // 인자값을 받을 때 리스트에 첫 번째 값은 프로그램 자체의 정보이며 그 다음 값은 현재 기기에서 쓰고 있는 네트워크 정보가 들어간다. 고로 코드를 시작했을 때 인자값이 2개가 아니라면 종료한다.

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드(자신의 lan카드로 들어오는 모든 패킷을 받는 모드)로 pcap를 열어 스니핑이 가능한 상태가 된다.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    } // 열지 못하면 어디에서 값을 받지 못했는지 메세지 출력 후 강제종료한다.

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        // 다음 패킷을 잡고 성공시 1을 반환한다.(코드를 이해하지 못했다)
        if (res == 0) continue; // timeout이 만기될 경우(0), 다시 패킷을 잡는다.
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        } // 에러와(-1), EOF(end of file, -2)시 루프를 종료한다.(EOF는 -1로 정의되어 있다 하는데 왜 -2?)

        struct ether_header *ep;
        struct ip *iph;
        struct tcphdr *tcph;
        // 이더넷 헤더, IP 헤더, TCP 헤더 구조체를 선언한다.

        ep = (struct ether_header *)packet;
        // 이더넷 헤더를 구한다.
        packet += sizeof(struct ether_header);
        // IP 헤더를 구하기 위해 이더넷 헤더만큼 오프셋.

        if (ntohs(ep->ether_type) == ETHERTYPE_IP){
        iph = (struct ip *)packet;
        // IP 패킷이면 IP 헤더를 구한다.
            if (iph->ip_p == IPPROTO_TCP){
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            // TCP 패킷이면 TCP 헤더를 구한다.

            printf("Src Mac : %s\n",ether_ntoa((struct ether_addr *)ep->ether_shost));
            printf("Dst Mac : %s\n",ether_ntoa((struct ether_addr *)ep->ether_dhost));
            // 이더넷 헤더에 있는 Mac 주소를 출력한다. (변환 함수 ether_ntoa 사용)
            printf("Src IP  : %s \n",inet_ntoa(iph->ip_src));
            printf("Dst IP  : %s \n",inet_ntoa(iph->ip_dst));
            // IP 헤더에 있는 IP 주소를 출력한다. (변환 함수 inet_ntoa 사용)
            printf("Src Port: %d\n" , ntohs(tcph->th_sport));
            printf("Dst Port: %d\n" , ntohs(tcph->th_dport));
            // TCP 헤더에 있는 포트를 출력한다. (변환 함수 ntohs 사용)
            printf("Total Bytes : %u\n", header->caplen);
            // 패킷의 총 바이트 크기 수를 출력한다.

            printf("TCP Payload : "); // TCP 페이로드를 출력한다.
            int length = header->len - sizeof (* ep);
            // length는 총 패킷 크기 - 이더넷 헤더 크기
            // (IP 헤더 크기 + TCP 헤더 크기 + TCP 페이로드 크기)
            int i=(iph->ip_hl*4)+(tcph->doff*4);
            // i는 IP 헤더 크기 + TCP 헤더 크기
            if (length-i>=16) length=i+16;
            // length-i를 하면 TCP 페이로드 길이를 구할 수 있음.
            // TCP 페이로드 길이가 16 이상이면 16으로 설정. 
            for(; i<length; i++){
                printf("%02x ", *(packet+i));
            }
            printf("\n\n");
            // TCP 페이로드 출력 후 개행(줄바꿈)을 찍어준다.
            }
        }
    }
    pcap_close(handle);
    // pcap 핸들을 닫아준다.
}