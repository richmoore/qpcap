#include <QDebug>

#include <pcap.h>

#include "qpcap.h"

static const int PCAP_TIMEOUT = 10000;

struct QPcapPrivate
{
    char errbuf[PCAP_ERRBUF_SIZE];
    QString lasterr;
    pcap_t *handle;
    bpf_program filter;
    pcap_pkthdr header;
    const u_char *packet;
};

QPcap::QPcap( QObject *parent )
    : QObject(parent)
{
    d = new QPcapPrivate;
    d->handle = 0;
    d->packet = 0;
}

QPcap::~QPcap()
{
    if (isValid())
        pcap_close(d->handle);
    delete d;
}

bool QPcap::isValid() const
{
    return (0 != d->handle);
}

QString QPcap::errorString() const
{
    if (isValid())
        return QString::fromLocal8Bit(pcap_geterr(d->handle));
    else
        return QString::fromLocal8Bit(d->errbuf);
}

QString QPcap::lookupDevice()
{
    char *dev = pcap_lookupdev(d->errbuf);
    if (!dev)
        return QString();

    return QString::fromLocal8Bit(dev);
}

bool QPcap::open( const QString &dev, int snaplen, bool promisc )
{
    d->handle = pcap_open_live( dev.toLocal8Bit().constData(),
                                snaplen,
                                promisc,
                                PCAP_TIMEOUT,
                                d->errbuf );

    return isValid();
}

bool QPcap::close()
{
    if (!isValid())
        return false;

    pcap_close(d->handle);
    d->handle = 0;

    return true;
}

bool QPcap::setFilter( const QString &filterexp )
{
    // TODO: sort out the netmask argument
    int status = pcap_compile(d->handle, &d->filter, filterexp.toLocal8Bit().constData(), 0, 0);
    if (status != 0)
        return false;

    status = pcap_setfilter(d->handle, &d->filter);
    if (status != 0)
        return false;

    return true;
}

bool QPcap::readPacket()
{
    d->packet = pcap_next( d->handle, &d->header );
    return (d->packet != 0);
}

const u_char *QPcap::packet() const
{
    return d->packet;
}

timeval QPcap::timeStamp() const
{
    return d->header.ts;
}

uint QPcap::capturedLength() const
{
    return d->header.caplen;
}

uint QPcap::packetLength() const
{
    return d->header.len;
}

