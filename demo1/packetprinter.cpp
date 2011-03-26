#include <QDebug>

#include "qpcapethernetpacket.h"
#include "qpcapippacket.h"
#include "qpcaptcppacket.h"

#include "packetprinter.h"

PacketPrinter::PacketPrinter( QObject *parent )
    : QObject(parent)
{
}

PacketPrinter::~PacketPrinter()
{
}

void PacketPrinter::print( const uchar *packet )
{
    QPcapEthernetPacket ether(packet);
    qDebug() << "== Ethernet ==";
    qDebug() << "Source:" << ether.sourceHost();
    qDebug() << "Dest:" << ether.destHost();

    if (ether.isIpPacket()) {
        QPcapIpPacket ip = ether.toIpPacket();
        qDebug() << "== IP ==";
        qDebug() << "Source:" << ip.source();
        qDebug() << "Dest:" << ip.dest();

        if (ip.isTcpPacket()) {
            QPcapTcpPacket tcp = ip.toTcpPacket();
            qDebug() << "== TCP ==";
            qDebug() << "Source Port:" << tcp.sourcePort();
            qDebug() << "Dest Port:" << tcp.destPort();

            if ( tcp.dataLength() ) {
                qDebug() << "== Data ==";
                qDebug() << tcp.data();
            }
        }
    }
}
