#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
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
#include <vector>

#include <pcap.h>
#include <pcap/sll.h>

#include <pcapparser.hpp>

const char *type_names[] = {"OTHER", "CONNECT", "SEND", "CLOSE"};

#define ERRBUF_SIZE 1024
static __thread char errbuf[ERRBUF_SIZE];

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

/* Parse data array for graphite plain-text metric
 * Incomplete string strored in buf, it's length in buflen
 *  @ return 0 - on success, -1 on - failure
 */
ssize_t process_packet(char *data, size_t len, char *buf, size_t &buflen,
                       size_t bufsize, std::vector<std::string> &result) {
    char *p, *token;
    size_t tlen;

    data[len] = '\0';
    p = data;
    token = strchr(p, '\n');

    while (token != NULL) {
        std::string s;
        s.reserve(token - data + buflen);
        if (buflen > 0) {
            s.append(buf, buflen);
            buflen = 0;
        }
        s.append(p, token);
        result.push_back(std::move(s));
        p = token + 1;
        token = strchr(p, '\n');
    }

    tlen = len - (p - data);
    if (tlen > 0) {
        /* incomplete, store to buffer */
        if (tlen + buflen >= bufsize) {
            /* overflow */
            errno = ENOSPC;
            return -1;
        } else if (buflen == 0) {
            strcpy(buf, p);
            buflen = tlen;
        } else {
            strcat(buf, p);
            buflen += tlen;
        }
    }

    return 0;
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

bool ip_find(const std::string &ip, const std::unordered_set<std::string> &ips,
             const std::vector<std::regex> &ips_regex) {
    if (ips.find(ip) != ips.end()) {
        return true;
    }
    for (const auto &r : ips_regex) {
        if (std::regex_search(ip, r)) {
            return true;
        }
    }
    return false;
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

ssize_t PCAPFile::decode_udp_packet(pcaprec_hdr_t *rec, struct ip *ip,
                                    uint8_t *end, packet &packet) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    struct udphdr *udp = (struct udphdr *) ((uint8_t *) ip + sizeof(struct ip));
#pragma GCC diagnostic pop
    uint16_t sport = ntohs(udp->uh_sport);
    uint16_t dport = ntohs(udp->uh_dport);
    std::string src = inet_ntoa(ip->ip_src);
    std::string dst = inet_ntoa(ip->ip_dst);

    if (!(sport == port && ip_find(src, ips, ips_regex)) &&
        !(dport == port && ip_find(dst, ips, ips_regex))) {
        return 0;
    }
    if (out_mode == PACKET) {
        if (print_ip_port(fout, rec, "UDP", src, sport, dst, dport) < 0 ||
            fprintf(fout, "\n") < 0) {
            fprintf(stderr, "out write: %s\n", strerror_t(errno));
            return -1;
        }
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    uint8_t *payload = (uint8_t *) udp + sizeof(struct udphdr);
    ssize_t size_payload = ntohs(ip->ip_len) - sizeof(struct udphdr);
    if (payload + size_payload > end) {
        size_payload = end - payload;
    }

    packet.proto = UDP;
    packet.ts.tv_sec = rec->ts_sec;
    packet.ts.tv_usec = rec->ts_usec;
    packet.message = NULL;
    packet.type = SEND;
    if (size_payload > 0) {
        packet.src_dst = "UDP " + src + ":" + std::to_string(sport) + " -> " +
                         dst + ":" + std::to_string(dport);
        payload[size_payload] = '\0';
        if (dport == port) {
            packet.message = (char *) payload;
        }
        if (out_mode == PACKET) {
            if (fprintf(fout, "%s\n", payload) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
    }
#pragma GCC diagnostic pop
    return size_payload;
}

ssize_t PCAPFile::decode_tcp_packet(pcaprec_hdr_t *rec, struct ip *ip,
                                    uint8_t *end, packet &packet) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    struct tcphdr *tcp = (struct tcphdr *) ((uint8_t *) ip + sizeof(struct ip));
#pragma GCC diagnostic pop
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);
    std::string src = inet_ntoa(ip->ip_src);
    std::string dst = inet_ntoa(ip->ip_dst);

    if (sport == port && ip_find(src, ips, ips_regex)) {
    } else if (dport == port && ip_find(dst, ips, ips_regex)) {
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
    }

    uint16_t offset = tcp->doff * 4;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    uint8_t *payload = (uint8_t *) tcp + offset;
    ssize_t size_payload = ntohs(ip->ip_len) - offset;
    if (payload + size_payload > end) {
        size_payload = end - payload;
    }

    packet.proto = TCP;
    packet.ts.tv_sec = rec->ts_sec;
    packet.ts.tv_usec = rec->ts_usec;
    packet.message = NULL;
    if (size_payload > 0) {
        payload[size_payload] = '\0';
        if (dport == port) {
            packet.message = (char *) payload;
        }
        if (out_mode == PACKET) {
            if (fprintf(fout, "%s\n", payload) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
    }

    if (dport == port) {
        if (tcp->syn) {
            packet.type = CONNECT;
        } else if (tcp->fin) {
            packet.type = CLOSE;
        } else if (size_payload > 0) {
            packet.type = SEND;
        } else {
            packet.type = OTHER;
        }
    } else {
        packet.type = OTHER;
    }

    if (packet.type != OTHER) {
        packet.src_dst = "TCP " + src + ":" + std::to_string(sport) + " -> " +
                         dst + ":" + std::to_string(dport);
    }

#pragma GCC diagnostic pop
    return size_payload;
}

ssize_t PCAPFile::decode_ip_packet(pcaprec_hdr_t *rec, struct ip *ip,
                                   uint8_t *end, packet &packet) {
    switch (ip->ip_p) {
    case IPPROTO_TCP:
        if (tcp) {
            return decode_tcp_packet(rec, ip, end, packet);
        }
        break;
    case IPPROTO_UDP:
        if (udp) {
            return decode_udp_packet(rec, ip, end, packet);
        }
        break;
    }

    return 0;
}

ssize_t PCAPFile::decode_packet(pcap_hdr_t *header, pcaprec_hdr_t *rec,
                                uint8_t *buf, uint8_t *end, packet &packet) {
    /* http://www.tcpdump.org/linktypes.html */
    switch (header->network) {
    case DLT_LINUX_SLL: {
        // struct sll_header *sll_header = (struct sll_header *) buf;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
        struct ip *ip =
            (struct ip *) ((uint8_t *) buf + sizeof(struct sll_header));
#pragma GCC diagnostic pop
        return decode_ip_packet(rec, ip, end, packet);
    } break;
    default:
        fprintf(stderr, "unnandled network type: %u\n", header->network);
        return -1;
    }
    return 0;
}

ssize_t PCAPFile::Next() {
    ssize_t n;
    if ((n = read_record(fd, &rec, wbuf, header.snaplen)) == -1) {
        return -1;
    }

    packet packet;
    ssize_t size = decode_packet(&header, &rec, wbuf, wbuf + n, packet);
    if (out_mode == METRIC) {
        if (packet.message) {
            std::vector<std::string> result;
            auto &b = buf[packet.src_dst];

            if (process_packet(packet.message, size, b.buf, b.len,
                               sizeof(b.buf), result) == 0 &&
                result.size() > 0) {
                if (fprintf(fout, "#%ld.%ld", packet.ts.tv_sec,
                            packet.ts.tv_usec) < 0) {
                    fprintf(stderr, "out write: %s\n", strerror_t(errno));
                    return -1;
                }
                if (fprintf(fout, " %s %s\n", packet.src_dst.c_str(),
                            type_names[packet.type]) < 0) {
                    fprintf(stderr, "out write: %s\n", strerror_t(errno));
                    return -1;
                }
                for (const auto &v : result) {
                    if (fprintf(fout, "%s\n", v.c_str()) < 0) {
                        fprintf(stderr, "out write: %s\n", strerror_t(errno));
                        return -1;
                    }
                }
            }
        } else if (packet.type != OTHER) {
            if (fprintf(fout, "#%ld.%ld", packet.ts.tv_sec, packet.ts.tv_usec) <
                0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
            if (fprintf(fout, " %s %s\n", packet.src_dst.c_str(),
                        type_names[packet.type]) < 0) {
                fprintf(stderr, "out write: %s\n", strerror_t(errno));
                return -1;
            }
        }
    }

    return size;
}

PCAPFile::PCAPFile(const char *filename, const char *out_filename,
                   OutMode out_mode, const std::vector<std::string> &ips,
                   const std::vector<std::string> &ips_regex, uint16_t port,
                   const std::vector<Protocol> &protocols) {
    // wbuf = NULL;
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error(std::string(filename) + ": " +
                                 std::string(strerror_t(errno)));
    }
    read_header(fd, &header, filename);
    this->out_mode = out_mode;
    if (out_filename == nullptr) {
        fout = stdout;
    } else {
        fout = fopen(out_filename, "a");
        if (fout == nullptr) {
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
    for (const auto &i : ips) {
        this->ips.insert(i);
    }
    this->ips_regex.reserve(ips_regex.size());
    for (const auto &i : ips_regex) {
        this->ips_regex.push_back(std::move(std::regex(i)));
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

PCAPFile::~PCAPFile() {
    if (fd) {
        close(fd);
    }
    if (fout != stdout) {
        fclose(fout);
    }
}
