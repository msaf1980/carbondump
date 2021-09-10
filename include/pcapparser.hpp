#ifndef __PCAPPARSER_HPP__
#define __PCAPPARSER_HPP__

#include <stdio.h>

#include <string>
#include <unordered_set>
#include <vector>
#include <regex>

enum Protocol { TCP = 0, UDP };

enum OutMode { METRIC = 0,  PACKET = 1 };


/* must be in sync with type_names */
enum Type { OTHER = 0, CONNECT = 1, SEND = 2, CLOSE = 3 };

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

typedef struct {
    Protocol proto;
    Type type;
    std::string src_dst;
    struct timeval ts;
    char *message;
} packet;

typedef struct {
  size_t len;
  char buf[32768];
} buffer;

class PCAPFile {
  public:
    PCAPFile(const char *filename, const char *out_filename, OutMode out_mode,
             const std::vector<std::string> &ips, const std::vector<std::string> &ips_regex, uint16_t port,
             const std::vector<Protocol> &protocols);

    ~PCAPFile();
    ssize_t Next();

  private:
    ssize_t decode_packet(pcap_hdr_t *header, pcaprec_hdr_t *rec, uint8_t *buf,
                          uint8_t *end, packet &packet);
    ssize_t decode_ip_packet(pcaprec_hdr_t *rec, struct ip *ip, uint8_t *end,
                             packet &packet);
    ssize_t decode_tcp_packet(pcaprec_hdr_t *rec, struct ip *ip, uint8_t *end,
                              packet &packet);
    ssize_t decode_udp_packet(pcaprec_hdr_t *rec, struct ip *ip, uint8_t *end,
                              packet &packet);
    int fd;
    FILE *fout;
    OutMode out_mode;
    pcap_hdr_t header;
    pcaprec_hdr_t rec;
    uint8_t wbuf[READ_BUF_SIZE];

    std::unordered_set<std::string> ips;
    std::vector<std::regex> ips_regex;
    uint16_t port;
    std::map<std::string, buffer> buf; // buffers for incomplete metrics
    bool tcp;
    bool udp;
};

#endif // __PCAPPARSER_HPP__