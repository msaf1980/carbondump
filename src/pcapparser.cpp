#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>

#include <pcap.h>
#include <pcap/sll.h>

#include <pcapparser.hpp>

#define ERRBUF_SIZE 1024
static __thread char errbuf[ERRBUF_SIZE];

OutMode out_mode;

const char *strerror_t(int errcode) {
#ifdef _GNU_SOURCE
    return strerror_r(errcode, errbuf, ERRBUF_SIZE);
#else
    if (strerror_r(errcode, errbuf, ERRBUF_SIZE) != 0) {
        snprintf(errbuf, ERRBUF_SIZE, "Unknown error %d", errcode);
    }
#endif
    return errbuf;
}

static void read_header(int fd, pcap_hdr_t *header, const char *filename) {
    ssize_t r = read(fd, header, sizeof(pcap_hdr_t));
    if (r == -1) {
        close(fd);
        throw std::runtime_error(std::string(filename) + ": " +
                                 std::string(strerror_t(errno)));
    } else if (r != sizeof(pcap_hdr_t)) {
        close(fd);
        throw std::runtime_error(std::string(filename) + ": file too small");
    }
    if (header->magic_number != 0xa1b2c3d4) {
        throw std::runtime_error(std::string(filename) +
                                 ": file type mismatch");
    }
}

static ssize_t read_record(int fd, pcaprec_hdr_t *rec, uint8_t *buf,
                           uint32_t bufsize) {
    ssize_t r = read(fd, rec, sizeof(pcaprec_hdr_t));
    if (r == -1) {
        return -1;
    } else if (r != sizeof(pcaprec_hdr_t)) {
        errno = EBADSLT;
        return -1;
    } else if (rec->incl_len > bufsize) {
        errno = EOVERFLOW;
        return -1;
    }
    r = read(fd, buf, rec->incl_len);
    if (r == -1) {
        return -1;
    } else if (r != rec->incl_len) {
        errno = EBADMSG;
        return -1;
    }
    return r;
}

static inline int print_flag(FILE *fout, const char *flag, int *first) {
    if (*first) {
        *first = 0;
        return fprintf(fout, "%s", flag);
    } else {
        return fprintf(fout, ",%s", flag);
    }
}

static int print_ip_port(FILE *fout, pcaprec_hdr_t *rec, const char *proto,
                         const std::string &src, uint16_t sport,
                         const std::string &dst, uint16_t dport) {
    if (fprintf(fout, "#%u.%u", rec->ts_sec, rec->ts_usec) < 0) {
        return -1;
    }

    if (fprintf(fout, " %s ->", src.c_str()) < 0) {
        return -1;
    }
    if (fprintf(fout, " %s", dst.c_str()) < 0) {
        return -1;
    }
    if (fprintf(fout, " %s %d ->", proto, sport) < 0) {
        return -1;
    }
    if (fprintf(fout, " %d", dport) < 0) {
        return -1;
    }
    return 0;
}

static int decode_udp_packet(FILE *fout, pcaprec_hdr_t *rec, struct ip *ip,
                             uint8_t *end, const std::vector<std::string> &ips,
                             int port) {
    struct udphdr *udp = (struct udphdr *) ((uint8_t *) ip + sizeof(struct ip));
    uint16_t sport = ntohs(udp->uh_sport);
    uint16_t dport = ntohs(udp->uh_dport);
    std::string src = inet_ntoa(ip->ip_src);
    std::string dst = inet_ntoa(ip->ip_dst);

    if (sport == port && std::find(ips.begin(), ips.end(), src) != ips.end()) {
    } else if (dport == port &&
               std::find(ips.begin(), ips.end(), dst) != ips.end()) {
    } else {
        return 0;
    }

    if (print_ip_port(fout, rec, "UDP", src, sport, dst, dport) < 0 ||
        fprintf(fout, "\n") < 0) {
        fprintf(stderr, "out write: %s\n", strerror_t(errno));
        return -1;
    }

    uint8_t *payload = (uint8_t *) udp + sizeof(struct udphdr);
    ssize_t size_payload = ntohs(ip->ip_len) - sizeof(struct udphdr);
    if (payload + size_payload > end) {
        size_payload = end - payload;
    }
    if (size_payload > 0) {
        if (out_mode == PACKET) {
            payload[size_payload] = '\0';
            if (fprintf(fout, "%s\n", payload) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        } else if (dport == port) {
            payload[size_payload] = '\0';
            if (fprintf(fout, "%s\n", payload) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
    }
    return 0;
}

static int decode_tcp_packet(FILE *fout, pcaprec_hdr_t *rec, struct ip *ip,
                             uint8_t *end, const std::vector<std::string> &ips,
                             uint16_t port) {
    struct tcphdr *tcp = (struct tcphdr *) ((uint8_t *) ip + sizeof(struct ip));
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);
    std::string src = inet_ntoa(ip->ip_src);
    std::string dst = inet_ntoa(ip->ip_dst);

    if (sport == port && std::find(ips.begin(), ips.end(), src) != ips.end()) {
    } else if (dport == port &&
               std::find(ips.begin(), ips.end(), dst) != ips.end()) {
    } else {
        return 0;
    }

    if (out_mode == PACKET) {
        if (print_ip_port(fout, rec, "TCP", src, sport, dst, dport) < 0 ||
            fprintf(fout, " [") < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        int first = 1;
        if (tcp->syn) {
            if (print_flag(fout, "SYN", &first) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
        if (tcp->fin) {
            if (print_flag(fout, "FIN", &first) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
        if (tcp->rst) {
            if (print_flag(fout, "RST", &first) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
        if (tcp->ack) {
            if (print_flag(fout, "ACK", &first) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
        if (tcp->psh) {
            if (print_flag(fout, "PUSH", &first) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
        if (tcp->urg) {
            if (print_flag(fout, "URG", &first) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
        if (fprintf(fout, "] Seq=%u AckSeq=%u\n", tcp->seq, tcp->ack_seq) < 0) {
            fprintf(stderr, "out write: %s\n", strerror_t(errno));
            return -1;
        }
    } else {
        if (tcp->syn && tcp->ack_seq == 0) {
            if (fprintf(fout, "#%u.%u", rec->ts_sec, rec->ts_usec) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
            if (fprintf(fout, " TCP %s:%d -> %s:%d CONNECT\n", src.c_str(),
                        sport, dst.c_str(), dport) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        } else if (tcp->fin && dport == port) {
            if (fprintf(fout, "#%u.%u", rec->ts_sec, rec->ts_usec) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
            if (fprintf(fout, " TCP %s:%d -> %s:%d FIN\n", src.c_str(), sport,
                        dst.c_str(), dport) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        } else if (tcp->rst) {
            if (fprintf(fout, "#%u.%u", rec->ts_sec, rec->ts_usec) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
            if (fprintf(fout, " TCP %s:%d -> %s:%d RST\n", src.c_str(), sport,
                        dst.c_str(), dport) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
    }

    uint16_t offset = tcp->doff * 4;
    uint8_t *payload = (uint8_t *) tcp + offset;
    ssize_t size_payload = ntohs(ip->ip_len) - offset;
    if (payload + size_payload > end) {
        size_payload = end - payload;
    }
    if (size_payload > 0) {
        if (out_mode == PACKET) {
            payload[size_payload] = '\0';
            if (fprintf(fout, "%s\n", payload) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        } else if (dport == port) {
            payload[size_payload] = '\0';
            if (fprintf(fout, "#%u.%u", rec->ts_sec, rec->ts_usec) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
            if (fprintf(fout, " TCP %s:%d -> %s:%d SEND\n", src.c_str(), sport,
                        dst.c_str(), dport) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
            if (fprintf(fout, "%s\n", payload) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
    }
    return 0;
}

static int decode_ip_packet(FILE *fout, pcaprec_hdr_t *rec, struct ip *ip,
                            uint8_t *end, const std::vector<std::string> &ips,
                            uint16_t port, bool tcp, bool udp) {
    switch (ip->ip_p) {
    case IPPROTO_TCP:
        if (tcp) {
            return decode_tcp_packet(fout, rec, ip, end, ips, port);
        }
        break;
    case IPPROTO_UDP:
        if (udp) {
            return decode_udp_packet(fout, rec, ip, end, ips, port);
        }
        break;
    }

    return 0;
}

static int decode_packet(FILE *fout, pcap_hdr_t *header, pcaprec_hdr_t *rec,
                         uint8_t *buf, uint8_t *end,
                         const std::vector<std::string> &ips, uint16_t port,
                         bool tcp, bool udp) {
    /* http://www.tcpdump.org/linktypes.html */
    switch (header->network) {
    case DLT_LINUX_SLL: {
        // struct sll_header *sll_header = (struct sll_header *) buf;
        struct ip *ip =
            (struct ip *) ((uint8_t *) buf + sizeof(struct sll_header));
        return decode_ip_packet(fout, rec, ip, end, ips, port, tcp, udp);
    } break;
    default:
        fprintf(stderr, "unnandled network type: %u\n", header->network);
        return -1;
    }
    return 0;
}

PCAPFile::~PCAPFile() {
    if (fd) {
        close(fd);
        // free(wbuf);
    }
}

int PCAPFile::Next() {
    ssize_t n;
    if ((n = read_record(fd, &rec, wbuf, header.snaplen)) == -1) {
        return -1;
    }

    return decode_packet(fout, &header, &rec, wbuf, wbuf + n, ips, port, tcp,
                         udp);
}

PCAPFile::PCAPFile(const char *filename, const char *out_filename,
                   const std::vector<std::string> &ips, uint16_t port,
                   const std::vector<Protocol> &protocols) {
    // wbuf = NULL;
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error(std::string(filename) + ": " +
                                 std::string(strerror_t(errno)));
    }
    read_header(fd, &header, filename);
    if (out_filename == NULL) {
        fout = stdout;
    } else {
        fout = fopen(out_filename, "a");
        if (fout == NULL) {
            throw std::runtime_error(std::string(out_filename) + ": " +
                                     std::string(strerror_t(errno)));
        }
    }
    if (header.version_major == 2 && header.version_minor == 4) {

    } else {
        throw std::runtime_error(std::string(filename) + "version mismatch :" +
                                 std::to_string(header.version_major) + "." +
                                 std::to_string(header.version_minor));
    }
    this->ips = ips;
    if (ips.size() > 1) {
        std::sort(this->ips.begin(), this->ips.end());
    }
    this->port = port;

    tcp = false;
    udp = false;
    for (const auto &i : protocols) {
        if (i == TCP) {
            tcp = true;
        }
        if (i == UDP) {
            udp = true;
        }
    }
}
