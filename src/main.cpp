#include <iostream>
#include <string>
#include <vector>

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>

#include <pcapparser.hpp>

int main(int argc, char **argv) {
    std::string filename;
    std::string out_filename;
    OutMode out_mode = METRIC;
    int port;
    std::vector<std::string> ips;
    std::vector<std::string> ips_regex;
    std::vector<Protocol> protocols;

    CLI::App app{"dump carbondump packets with pcap (at now plain text only)"};
    app.add_option("-f,--file", filename, "PCAP file name")->required();

    app.add_option("-w,--write", out_filename, "output to file");
    app.add_option("-m,--mode", out_mode, "out mode")
        ->transform(CLI::CheckedTransformer(std::map<std::string, int>(
            {{"packet", PACKET}, {"metric", METRIC}})));

    app.add_option("-p,--port", port, "carbon server port")
        ->default_val(2003)
        ->check(CLI::PositiveNumber);
    app.add_option("-i,--ips", ips, "IPs of carbon servers to extract");
    app.add_option("--ips-regex", ips_regex,
                   "Regexps for IPs of carbon servers to extract");
    app.add_option("-P,--protocols", protocols, "protocols")
        ->transform(CLI::CheckedTransformer(
            std::map<std::string, int>({{"tcp", TCP}, {"udp", UDP}})));
    CLI11_PARSE(app, argc, argv);

    if (protocols.size() == 0) {
        protocols = {TCP, UDP};
    }

    if (ips.size() == 0 && ips_regex.size() == 0) {
        std::cerr << "ips or ips regex not set" << std::endl;
    }

    try {
        const char *out_fname;
        if (out_filename.size() == 0) {
            out_fname = NULL;
        } else {
            out_fname = out_filename.c_str();
        }
#pragma GCC diagnostic push
        PCAPFile pcapFile =
            PCAPFile(filename.c_str(), out_fname, out_mode, ips, ips_regex,
                     static_cast<uint16_t>(port), protocols);
        while (pcapFile.Next() != -1) {
        }
    } catch (std::exception &ex) {
        std::cout << ex.what() << std::endl;
        exit(1);
    }

    return 0;
}
