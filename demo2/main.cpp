#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>

#include "qpcap.h"
#include "qpcapethernetpacket.h"
#include "qpcapippacket.h"
#include "qpcaptcppacket.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    QPcap pcap;
    
    QString device = pcap.lookupDevice();
    if ( device.isEmpty() ) {
        qDebug() << "Lookup device failed, " << pcap.errorString();
        return 1;
    }
    else {
        qDebug() << "Lookup device" << device;
    }

    bool ok;
    ok = pcap.open( device, 65535, true );
    if (!ok) {
        qDebug() << "Unable to open, " << pcap.errorString();
        return 1;
    }

    ok = pcap.setFilter( QString("bad filter") );
    if (!ok) {
        qDebug() << "bad filter failed (good!), " << pcap.errorString();
    }

    //ok = pcap.setFilter( QString("host xmelegance.org and port 80") );
    ok = pcap.setFilter( QString("ip") );
    if (!ok) {
        qDebug() << "filter failed, " << pcap.errorString();
    }

    for (int i=0; i < 3; i++ ) {
        ok = pcap.readPacket();
        if (!ok) {
            qDebug() << "Failed to read a packet, " << pcap.errorString();
            //return 1;
        }

        QPcapHeader header = pcap.header();
        qDebug() << "Got one packet, length is " << header.packetLength() << "captured " << header.capturedLength();

        const u_char *packet = pcap.packet();

        QPcapEthernetPacket ether(packet);
        qDebug() << "Source:" << ether.sourceHost();
        qDebug() << "Dest:" << ether.destHost();

        QPcapIpPacket ip = ether.toIpPacket();
        qDebug() << "Source:" << ip.source();
        qDebug() << "Dest:" << ip.dest();

        QByteArray bytes( (const char *)packet, header.capturedLength() );
        qDebug() << bytes.toHex();
    }

    pcap.close();
}
