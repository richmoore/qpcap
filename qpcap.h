#ifndef QPCAP_H
#define QPCAP_H

#include <QString>

class QPcap
{
public:
    QPcap();
    ~QPcap();

    bool isValid() const;

    QString errorString() const;

    QString lookupDevice();

    bool open( const QString &dev, int snaplen, bool promisc );
    bool close();

    bool readPacket();

    bool setFilter( const QString &filter );

    // Information about the latest packet
    timeval timeStamp() const;
    uint capturedLength() const;
    uint packetLength() const;
    const u_char *packet() const;

private:
    struct QPcapPrivate *d;
};

#endif // QPCAP_H

