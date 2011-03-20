#include <QDebug>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "qpcappacket.h"

QPcapEthernetPacket::QPcapEthernetPacket()
    : packet(0)
{
}

QPcapEthernetPacket::QPcapEthernetPacket( const uchar *pkt )
    : packet(pkt)
{
}

QPcapEthernetPacket::~QPcapEthernetPacket()
{
    // We don't own the packet
}

bool QPcapEthernetPacket::isValid() const
{
    return (0 != packet);
}


QString QPcapEthernetPacket::sourceHost() const
{
    const ether_header *ether = reinterpret_cast<const ether_header *>(packet);
    const ether_addr *src = reinterpret_cast<const ether_addr *>(&ether->ether_shost);

    return QString::fromAscii( ether_ntoa(src) );
}

QString QPcapEthernetPacket::destHost() const
{
    const ether_header *ether = reinterpret_cast<const ether_header *>(packet);
    const ether_addr *dst = reinterpret_cast<const ether_addr *>(&ether->ether_dhost);

    return QString::fromAscii( ether_ntoa(dst) );
}

ushort QPcapEthernetPacket::frameType() const
{
    const ether_header *ether = reinterpret_cast<const ether_header *>(packet);
    return ntohs(ether->ether_type);
}

bool QPcapEthernetPacket::isIpPacket() const
{
    return ETHERTYPE_IP == frameType();
}

QPcapIpPacket QPcapEthernetPacket::toIpPacket() const
{
    if (frameType() != ETHERTYPE_IP )
        return QPcapIpPacket();

    const uchar *payload = packet + sizeof(ether_header);
    return QPcapIpPacket(payload);
}

//
// IP packet
//

QPcapIpPacket::QPcapIpPacket()
    : packet(0)
{

}

QPcapIpPacket::QPcapIpPacket( const uchar *pkt )
    : packet(pkt)
{
}

QPcapIpPacket::~QPcapIpPacket()
{
    // We don't own the packet
}

bool QPcapIpPacket::isValid() const
{
    return (0 != packet);
}

int QPcapIpPacket::version() const
{
    const iphdr *ip = reinterpret_cast<const iphdr *>(packet);
    return ip->version;
}

int QPcapIpPacket::headerLength() const
{
    const iphdr *ip = reinterpret_cast<const iphdr *>(packet);
    return ip->ihl * 4; // The value in the packet is divided by 4
}

int QPcapIpPacket::protocol() const
{
    const iphdr *ip = reinterpret_cast<const iphdr *>(packet);
    return ip->protocol;
}

QHostAddress QPcapIpPacket::source() const
{
    const iphdr *ip = reinterpret_cast<const iphdr *>(packet);
    return QHostAddress( ntohl(ip->saddr) );
}

QHostAddress QPcapIpPacket::dest() const
{
    const iphdr *ip = reinterpret_cast<const iphdr *>(packet);
    return QHostAddress( ntohl(ip->daddr) );
}

int QPcapIpPacket::length() const
{
    const iphdr *ip = reinterpret_cast<const iphdr *>(packet);
    return ntohs( ip->tot_len );
}

bool QPcapIpPacket::isTcpPacket() const
{
    return (protocol() == TcpProtocol);
}

QPcapTcpPacket QPcapIpPacket::toTcpPacket() const
{
    if (protocol() != TcpProtocol)
        return QPcapTcpPacket();

    const uchar *payload = packet + headerLength();
    return QPcapTcpPacket(payload, length()-headerLength());
}


//
// TCP packet
//

QPcapTcpPacket::QPcapTcpPacket()
    : packet(0), length(0)
{
}

QPcapTcpPacket::QPcapTcpPacket( const uchar *pkt, int len )
    : packet(pkt), length(len)
{
}

QPcapTcpPacket::~QPcapTcpPacket()
{
    // We don't own the packet
}

bool QPcapTcpPacket::isValid() const
{
    return (packet != 0);
}

ushort QPcapTcpPacket::sourcePort() const
{
    const tcphdr *tcp = reinterpret_cast<const tcphdr *>(packet);
    return ntohs(tcp->source);
}

ushort QPcapTcpPacket::destPort() const
{
    const tcphdr *tcp = reinterpret_cast<const tcphdr *>(packet);
    return ntohs(tcp->dest);
}

uint QPcapTcpPacket::sequenceNumber() const
{
    const tcphdr *tcp = reinterpret_cast<const tcphdr *>(packet);
    return ntohl(tcp->seq);
}

uint QPcapTcpPacket::ackNumber() const
{
    const tcphdr *tcp = reinterpret_cast<const tcphdr *>(packet);
    return ntohl(tcp->ack_seq);
}

int QPcapTcpPacket::headerLength() const
{
    const tcphdr *tcp = reinterpret_cast<const tcphdr *>(packet);
    return tcp->doff * 4; // The value in the packet is divided by 4
}

int QPcapTcpPacket::dataLength() const
{
    return length-headerLength();
}

QByteArray QPcapTcpPacket::data() const
{
    return QByteArray::fromRawData( reinterpret_cast<const char *>(packet+headerLength()), dataLength() );
}

