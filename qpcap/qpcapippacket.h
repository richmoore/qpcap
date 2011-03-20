// -*- c++ -*-

#ifndef QPCAPIPPACKET_H
#define QPCAPIPPACKET_H

#include <QHostAddress>

class QPcapTcpPacket;

class QPcapIpPacket
{
public:
    enum IpProtocol {
        IcmpProtocol = 1,
        IgmpProtocol = 2,
        TcpProtocol = 6,
        UdpProtocol = 17,
        Ip6Protocol = 41,
        Icmp6Protocol = 58
    };

    QPcapIpPacket();
    QPcapIpPacket( const uchar *packet );

    ~QPcapIpPacket();

    bool isValid() const;

    int version() const;
    int headerLength() const;

    int protocol() const;

    QHostAddress source() const;
    QHostAddress dest() const;

    int length() const;

    bool isTcpPacket() const;
    QPcapTcpPacket toTcpPacket() const;

private:
    const uchar *packet;
};

#endif // QPCAPIPPACKET_H
