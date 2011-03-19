// -*- c++ -*-

#ifndef QPCAPPACKET_H_H
#define QPCAPPACKET_H_H

#include <QHostAddress>
#include <QString>

class QPcapIpPacket;

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
    QPcapIpPacket();
    QPcapIpPacket( const uchar *packet );

    ~QPcapIpPacket();

    bool isValid() const;

    int version() const;
    int headerLength() const;

    int protocol() const;

    QHostAddress source() const;
    QHostAddress dest() const;

private:
    const uchar *packet;
};

#endif // QPCAPPACKET_H_H
