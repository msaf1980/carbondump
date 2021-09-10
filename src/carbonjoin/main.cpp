#include <string.h>

#include <stdexcept>

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <algorithm>
#include <utility>

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>

#include <strcmp.hpp>
#include <strutils.hpp>

enum OutMode { METRIC = 0 };

void transformPrefix(std::string metric) {
    for (auto &c : metric) {
        if (c == '.') {
            break;
        }
    }
}

int main(int argc, char **argv) {
    std::vector<std::string> filenames;
    std::string out_filename;
    std::string postfix("LT");
    std::string values("0:100");

    bool no_transorm = false;

    CLI::App app{"join and process metric files, extracted with carbondump"};
    app.add_option("-f,--file", filenames, "metrics file names");

    app.add_option("-w,--write", out_filename, "output to file");

    app.add_flag("-n", no_transorm, "disable transform metric names");

    CLI11_PARSE(app, argc, argv);

    if (filenames.size() == 0) {
        std::cerr << "file not set" << std::endl;
        return 1;
    }
    if (out_filename.size() == 0) {
        std::cerr << "out file not set" << std::endl;
        return 1;
    }

    std::fstream fout;
    fout.open(out_filename, std::ios::out);
    if (fout.fail()) {
        std::cerr << out_filename << ": " << strerror(errno) << "\n";
        return 1;
    }

    std::multimap<std::string, std::string> metrics;

    for (const auto &filename : filenames) {
        std::fstream fin;
        std::string line;
        std::string ts;
        fin.open(filename, std::ios::in);
        if (fin.fail()) {
            std::cerr << filename << ": " << strerror(errno) << "\n";
            return 1;
        }
        while (std::getline(fin, line)) {
            if (line.size() > 0) {
                if (line[0] == '#' && strutils::ends_with(line, " SEND")) {
                    // std::cout << line << "\n";
                    ts = std::move(line);
                } else {
                    auto ss = strutils::split(line, ' ');
                    if (ss.size() == 3) {
                        std::string m(ss[0]);
                        metrics.insert(std::make_pair(ts, std::move(m)));
                    }
                }
            }
        }
        fin.close();
    }

    for (const auto &it : metrics) {
        if (no_transorm) {
            fout << it.second;
        } else {
            if (it.second.find(';') == std::string::npos) {
                /* no tags */
                auto ss = strutils::split(it.second, '.');
                if (ss.size() < 2) {
                    continue;
                }
                fout << ss[0] << postfix;
                for (size_t i = 1; i < ss.size(); i++) {
                    fout << '.' << ss[i];
                }
            } else {
                /* tags */
                auto ss = strutils::split(it.second, ';');
                if (ss.size() < 2 || ss[1].find('=') == std::string::npos) {
                    continue;
                }
                fout << ss[0];
                for (size_t i = 1; i < ss.size(); i++) {
                    std::string sl(ss[i]);
                    std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
                    if (strutils::starts_with(sl, "env") ||
                        strutils::starts_with(sl, "team") ||
                        strutils::starts_with(sl, "proj") ||
                        strutils::starts_with(sl, "subproj") ||
                        /* kubernetes */
                        strutils::starts_with(sl, "cluster") ||
                        strutils::starts_with(sl, "namespace")) {
                        fout << ';' << ss[i] << postfix;
                    } else {
                        fout << ';' << ss[i];
                    }
                }
            }
        }
        fout << "\n";
    }
    fout.close();

    return 0;
}
