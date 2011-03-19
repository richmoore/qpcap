#include <QDebug>

#include "qpcappacket.h"
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
    }
}
