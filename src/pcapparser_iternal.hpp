#ifndef __PCAPPARSER_ITERNAL_HPP__
#define __PCAPPARSER_ITERNAL_HPP__

/* for unit tests */

#include <string>
#include <vector>

ssize_t process_packet(char *data, size_t len, char *buf, size_t &buflen, size_t bufsize, std::vector<std::string> &result);

#endif // __PCAPPARSER_ITERNAL_HPP__