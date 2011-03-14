#include <QDebug>
#include <QSocketNotifier>

#include <pcap.h>

#include "qpcap.h"

static const int PCAP_TIMEOUT = 10000;

struct QPcapPrivate
{
    char errbuf[PCAP_ERRBUF_SIZE];
    QString lasterr;
    pcap_t *handle;
    bpf_program filter;
    QPcapHeader header;
    const u_char *packet;
    QSocketNotifier *notifier;
};

QPcapHeader::QPcapHeader()
{
}

QPcapHeader::~QPcapHeader()
{
    // We don't own the header
}

void QPcapHeader::setHeader( const struct pcap_pkthdr *header )
{
    this->header = header;
}

timeval QPcapHeader::timeStamp() const
{
    return header->ts;
}

uint QPcapHeader::capturedLength() const
{
    return header->caplen;
}

uint QPcapHeader::packetLength() const
{
    return header->len;
}


QPcap::QPcap( QObject *parent )
    : QObject(parent)
{
    d = new QPcapPrivate;
    d->handle = 0;
    d->packet = 0;
    d->notifier = 0;
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
    if (d->notifier)
        stop();

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

void QPcap::packet_callback( uchar *self, const pcap_pkthdr *header, const uchar *packet )
{
    qDebug() << "packet_callback";

    QPcap *qpcap = reinterpret_cast<QPcap *>(self);
    qpcap->d->header.setHeader( header );
    qpcap->d->packet = packet;

    qpcap->packetReady();
}

void QPcap::dataAvailable()
{
    pcap_dispatch( d->handle, -1 /* all packets*/, (pcap_handler)&QPcap::packet_callback, (uchar *)this );
}


void QPcap::start()
{
    if (!isValid())
        return;

    int fd = pcap_get_selectable_fd(d->handle);
    d->notifier = new QSocketNotifier( fd, QSocketNotifier::Read, this );
    connect( d->notifier, SIGNAL(activated(int)), this, SLOT(dataAvailable()) );
    d->notifier->setEnabled(true);
}

void QPcap::stop()
{
    if (!isValid())
        return;

    pcap_breakloop( d->handle );
    delete d->notifier;
    d->notifier = 0;
}

bool QPcap::readPacket()
{
    if (!isValid())
        return false;

    pcap_pkthdr *header;
    int result = pcap_next_ex( d->handle, &header, &d->packet );
    if (result < 1)
        return false;
    d->header.setHeader(header);

    return true;
}

QPcapHeader QPcap::header() const
{
    return d->header;
}

const u_char *QPcap::packet() const
{
    return d->packet;
}


