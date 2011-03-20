// -*- c++ -*-

#ifndef QPCAPTCPPACKET_H
#define QPCAPTCPPACKET_H

#include <QByteArray>

class QPcapTcpPacket
{
public:
    QPcapTcpPacket();
    QPcapTcpPacket( const uchar *packet, int length );

    ~QPcapTcpPacket();

    bool isValid() const;

    ushort sourcePort() const;
    ushort destPort() const;

    uint sequenceNumber() const;
    uint ackNumber() const;

    int headerLength() const;

    int dataLength() const;
    QByteArray data() const;

private:
    const uchar *packet;
    int length;
};

#endif // QPCAPTCPPACKET_H
