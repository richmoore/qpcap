/**
 * Copyright 2011-2012 Richard J. Moore rich@kde.org
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) version 3, or any
 * later version accepted by the membership of KDE e.V. (or its
 * successor approved by the membership of KDE e.V.), which shall
 * act as a proxy defined in Section 6 of version 3 of the license.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public 
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QPCAP_H
#define QPCAP_H

#include <QObject>
#include <QString>

#include <sys/time.h>

class QPcapHeader
{
public:
    QPcapHeader( const struct pcap_pkthdr *header );
    QPcapHeader();
    ~QPcapHeader();

    bool isValid() const;

    timeval timeStamp() const;
    uint capturedLength() const;
    uint packetLength() const;

private:
    const struct pcap_pkthdr *header;
    friend class QPcap;
};

class QPcap : public QObject
{
    Q_OBJECT
public:
    QPcap( QObject *parent=0 );
    ~QPcap();

    bool isValid() const;

    QString errorString() const;

    QString lookupDevice();

    bool open( const QString &dev, int snaplen=65536, bool promisc=true );
    bool close();

    bool readPacket();

    void start();
    void stop();

    bool setFilter( const QString &filter );

    bool isBlocking() const;
    void setBlocking( bool enable );

    QPcapHeader header() const;
    const uchar *packet() const;

signals:
    void packetReady();
    void packetReady( const uchar *packet );
    void packetReady( QPcapHeader header, const uchar *packet );

private slots:
    void dataAvailable();

private:
    static void packet_callback( uchar *self, const struct pcap_pkthdr *header, const uchar *packet );

private:
    struct QPcapPrivate *d;
};

#endif // QPCAP_H

