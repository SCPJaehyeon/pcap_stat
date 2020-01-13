TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        cpp\main.cpp \
        cpp\pcap_constat.cpp \
        cpp\pcap_epstat.cpp \
        cpp\show.cpp

HEADERS += \
    header\pcap_stat.h
