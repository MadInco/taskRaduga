#include "PCAP.h"
#include <iostream>
#include <fstream>

constexpr  void __32_swab(uint32_t src, uint32_t& dst) {
    dst = ((src >> 24) & 0xff) | ((src << 8) & 0xff0000) | ((src >> 8) & 0xff00) | ((src << 24) & 0xff000000);
};
constexpr  void __32_swab(int32_t src, int32_t& dst) {
    dst = ((src >> 24) & 0xff) | ((src << 8) & 0xff0000) | ((src >> 8) & 0xff00) | ((src << 24) & 0xff000000);
};
constexpr  void __16_swab(uint16_t src, uint16_t& dst) {
    dst = (src >> 8) | (src << 8);
};
PCAPReader::PCAPReader(const std::string& fileName) : fileName(fileName), packets(0), payload(0){
    pcap_fl_hdr pcap, pcap_swapped;
    pcap_pckt_hdr phdr, phdr_swapped;
    std::ifstream in(fileName, std::ios::binary);

    if (in.is_open()) {
        in.read((char*)&pcap_swapped, sizeof(pcap_swapped));
        if (pcap_swapped.isSwapped()) {
            __32_swab(pcap_swapped.magic_number, pcap.magic_number);
            __16_swab(pcap_swapped.version_major, pcap.version_major);
            __16_swab(pcap_swapped.version_minor, pcap.version_minor);
            __32_swab(pcap_swapped.thiszone, pcap.thiszone);
            __32_swab(pcap_swapped.sigfigs, pcap.sigfigs);
            __32_swab(pcap_swapped.snaplen, pcap.snaplen);
            __32_swab(pcap_swapped.network, pcap.network);
        }
        else {
            pcap = pcap_swapped;
        }
        while (in.good()) {
            in.read((char*)&phdr_swapped, sizeof(phdr_swapped));
            if (in.eof())
                break;
            if (pcap_swapped.isSwapped()) {
                __32_swab(phdr_swapped.ts_sec, phdr.ts_sec);
                __32_swab(phdr_swapped.ts_usec, phdr.ts_usec);
                __32_swab(phdr_swapped.incl_len, phdr.incl_len);
                __32_swab(phdr_swapped.orig_len, phdr.orig_len);
            }
            else
                phdr = phdr_swapped;
            payload += phdr.orig_len;
            packets++;
            in.seekg(phdr.orig_len, std::ios_base::cur);//Перескакиваем сами данные
            if (in.eof())
                break;
        }
        in.close();
    }
    else {
        std::cout << "File is not opened : " << fileName << std::endl;
    }
}
// Количество пакетов в файле
uint64_t PCAPReader::packetsCount() const{
    return packets;
}

// Общий объём полезной нагрузки (без учёта заголовков)
uint64_t PCAPReader::payloadSize() const {
    return payload;
}