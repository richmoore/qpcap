TEMPLATE = app
TARGET = demo1

QT += network

LIBS    += -Wl,-rpath,../qpcap -L../qpcap -lqpcap
INCLUDEPATH += ../qpcap

SOURCES += packetprinter.cpp main.cpp
HEADERS += packetprinter.h
