#pragma once

#include <string>
#define PCAP_MAGIC                      0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC              0xd4c3b2a1
#define PCAP_NSEC_MAGIC                 0xa1b23c4d
#define PCAP_SWAPPED_NSEC_MAGIC         0x4d3cb2a1
#pragma pack(push, 1)
struct pcap_fl_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
    bool isSwapped() {
        if (magic_number == PCAP_SWAPPED_MAGIC)
            return true;
        return false;
    }
};
struct pcap_pckt_hdr {//16
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};
#pragma pack(pop)
class PCAPReader {
    const std::string fileName;
    uint64_t packets;
    uint64_t payload;
public:
    explicit PCAPReader(const std::string &fileName);

    // Количество пакетов в файле
    uint64_t packetsCount() const;

    // Общий объём полезной нагрузки (без учёта заголовков)//кол-во байтов данных
    uint64_t payloadSize() const;
};
