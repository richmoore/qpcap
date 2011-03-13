#ifndef QPCAP_H
#define QPCAP_H

#include <QObject>
#include <QString>

#include <sys/time.h>

class QPcap : public QObject
{
    Q_OBJECT
public:
    QPcap( QObject *parent=0 );
    ~QPcap();

    bool isValid() const;

    QString errorString() const;

    QString lookupDevice();

    bool open( const QString &dev, int snaplen, bool promisc );
    bool close();

    bool readPacket();

    void start();
    void stop();

    bool setFilter( const QString &filter );

    // Information about the latest packet
    timeval timeStamp() const;
    uint capturedLength() const;
    uint packetLength() const;
    const uchar *packet() const;

signals:
    void packetReady();

private slots:
    void dataAvailable();

private:
    static void packet_callback( uchar *self, const struct pcap_pkthdr *header, const uchar *packet );

private:
    struct QPcapPrivate *d;
};

#endif // QPCAP_H
