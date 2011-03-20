// -*- c++ -*-

#ifndef QPCAPPACKET_H_H
#define QPCAPPACKET_H_H

#include <QHostAddress>
#include <QString>

class QPcapIpPacket;
class QPcapTcpPacket;

class QPcapEthernetPacket
{
public:
    QPcapEthernetPacket();
    QPcapEthernetPacket( const uchar *packet );

    ~QPcapEthernetPacket();

    bool isValid() const;

    QString sourceHost() const;
    QString destHost() const;
    ushort frameType() const;

    bool isIpPacket() const;
    QPcapIpPacket toIpPacket() const;

private:
    const uchar *packet;
};

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

    QPcapTcpPacket toTcpPacket() const;

private:
    const uchar *packet;
};

class QPcapTcpPacket
{
public:
    QPcapTcpPacket();
    QPcapTcpPacket( const uchar *packet );

    ~QPcapTcpPacket();

    bool isValid() const;

private:
    const uchar *packet;
};

#endif // QPCAPPACKET_H_H
