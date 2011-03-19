// -*- c++ -*-

#ifndef PACKET_PRINTER_H
#define PACKET_PRINTER_H

#include <QObject>

class PacketPrinter : public QObject
{
    Q_OBJECT
public:
    PacketPrinter( QObject *parent=0 );
    ~PacketPrinter();

public slots:
    void print( const uchar *packet );
};

#endif // PACKET_PRINTER_H
