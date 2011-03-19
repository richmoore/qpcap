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

    QPcapIpPacket ip = ether.ipPacket();
    qDebug() << "== IP ==";
    qDebug() << "Source:" << ip.source();
    qDebug() << "Dest:" << ip.dest();
}
