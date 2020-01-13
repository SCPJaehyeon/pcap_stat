TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        main.cpp \
        pcap_constat.cpp \
        pcap_epstat.cpp \
        show.cpp

HEADERS += \
    pcap_stat.h
