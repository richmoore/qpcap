// -*- c++ -*-

#ifndef QPCAPETHERNETPACKET_H
#define QPCAPETHERNETPACKET_H

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

#endif // QPCAPETHERNETPACKET_H
