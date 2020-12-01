#define CATCH_CONFIG_MAIN

#include <string.h>

#include <catch2/catch.hpp>

#include <pcapparser_iternal.hpp>

TEST_CASE("partial_buffer", "[process_packet]") {
    char data[4096];
    char buf[4096];
    size_t len, bufsize, buflen;
    std::vector<std::string> result;
    ssize_t ret;

    bufsize = sizeof(buf);
    buflen = 0;

    /* first packet */
    strcpy(data, "a1.b1.c1 12 13\na2.b2.c2 22 23\na3.b3.c3 3");
    len = strlen(data);
    ret = process_packet(data, len, buf, buflen, bufsize, result);
    REQUIRE(ret == 0);
    REQUIRE_THAT(result,
                 Catch::Matchers::UnorderedEquals(std::vector<std::string>{
                     "a1.b1.c1 12 13", "a2.b2.c2 22 23"}));
    REQUIRE(buflen == 10);
    if (buflen > 0) {
        REQUIRE(std::string(buf) == "a3.b3.c3 3");
    }

    /* second packet */
    strcpy(data, "2 33\na4.b4.c4 42 43\n");
    len = strlen(data);
    ret = process_packet(data, len, buf, buflen, bufsize, result);
    REQUIRE(ret == 0);
    REQUIRE_THAT(result,
                 Catch::Matchers::UnorderedEquals(std::vector<std::string>{
                     "a1.b1.c1 12 13", "a2.b2.c2 22 23", "a3.b3.c3 32 33",
                     "a4.b4.c4 42 43"}));
    REQUIRE(buflen == 0);

    result.clear();
    strcpy(data, "a5.b5.c5 52 53\n");
    len = strlen(data);
    ret = process_packet(data, len, buf, buflen, bufsize, result);
    REQUIRE(ret == 0);
    REQUIRE_THAT(result, Catch::Matchers::UnorderedEquals(
                             std::vector<std::string>{"a5.b5.c5 52 53"}));
    REQUIRE(buflen == 0);
}
