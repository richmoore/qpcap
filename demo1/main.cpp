#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>

#include "qpcap.h"

#include "packetprinter.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    QPcap pcap;
    
    QString device = pcap.lookupDevice();
    if ( device.isEmpty() ) {
        qDebug() << "Lookup device failed, " << pcap.errorString();
        return 1;
    }

    bool ok;
    ok = pcap.open( device, 65535, true );
    if (!ok) {
        qDebug() << "Unable to open, " << pcap.errorString();
        return 1;
    }

    ok = pcap.setFilter( QString("ip") );
    if (!ok) {
        qDebug() << "filter failed, " << pcap.errorString();
        return 1;
    }

    PacketPrinter printer;
    printer.connect( &pcap, SIGNAL(packetReady(const uchar *)), SLOT(print(const uchar *)) );

    pcap.start();

    app.exec();

    pcap.close();
}
