#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>

#include "qpcap.h"

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
#if 0
    ok = pcap.setFilter( QString("host xmelegance.org and port 80") );
    if (!ok) {
        qDebug() << "filter failed, " << pcap.errorString();
    }
#endif
    for (int i=0; i < 3; i++ ) {
        ok = pcap.readPacket();
        if (!ok) {
            qDebug() << "Failed to read a packet, " << pcap.errorString();
            //return 1;
        }

        qDebug() << "Got one packet, length is " << pcap.packetLength() << "captured " << pcap.capturedLength();

        const u_char *packet = pcap.packet();
        QByteArray bytes( (const char *)packet, pcap.capturedLength() );
        qDebug() << bytes.toHex();
    }

    pcap.start();

    app.exec();

    pcap.close();
}
