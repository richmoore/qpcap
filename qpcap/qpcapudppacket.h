// -*- c++ -*-

#ifndef QPCAPUDPPACKET_H
#define QPCAPUDPPACKET_H

#include <QByteArray>

class QPcapUdpPacket
{
public:
    QPcapUdpPacket();
    QPcapUdpPacket( const uchar *packet, int length );

    ~QPcapUdpPacket();

    bool isValid() const;

    ushort sourcePort() const;
    ushort destPort() const;

    int dataLength() const;
    QByteArray data() const;

private:
    const uchar *packet;
    int length;
};

#endif // QPCAPUDPPACKET_H
