#ifndef __PCAPPARSER_HPP__
#define __PCAPPARSER_HPP__

#include <stdio.h>

#include <string>
#include <vector>

enum Protocol { TCP = 0, UDP };

enum OutMode { PACKET = 0, METRIC = 1 };

extern OutMode out_mode;

#define READ_BUF_SIZE 65572

/* https://wiki.wireshark.org/Development/LibpcapFileFormat */
typedef struct pcap_hdr_s {
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcaprec_hdr_t;

class PCAPFile {
  public:
    PCAPFile(const char *filename, const char *out_filename, const std::vector<std::string> &ips,
             uint16_t port, const std::vector<Protocol> &protocols);

    ~PCAPFile();
    int Next();

  private:
    int fd;
    FILE *fout;
    pcap_hdr_t header;
    pcaprec_hdr_t rec;
    uint8_t buf[READ_BUF_SIZE];
    uint8_t wbuf[READ_BUF_SIZE];

    std::vector<std::string> ips;
    uint16_t port;
    bool tcp;
    bool udp;
};

#endif // __PCAPPARSER_HPP__