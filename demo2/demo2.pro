TEMPLATE = app
TARGET = demo2

QT += network

LIBS    += -Wl,-rpath,../qpcap -L../qpcap -lqpcap
INCLUDEPATH += ../qpcap

SOURCES += main.cpp
HEADERS += 
