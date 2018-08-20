#ifndef _PROTOPARSE_H_
#define _PROTOPARSE_H_
#include <stdint.h>
#include <unordered_map>


class L7Parser {
public:
    const unsigned char* packet;
    struct ip* ip_hdr;
    uint8_t    ip_hdr_len;

    int        l4_proto;
    uint16_t   l4_total_len;
    const unsigned char* l4_start;

    int         l7_proto;
    uint16_t    l7_total_len;
    const char* l7_start;
    enum L7Proto {
        HTTP, NONE
    };
    std::unordered_map<std::string, std::string> http_hdr;
    //////////////////////////////////////////////////
    L7Parser(const unsigned char* _packet = NULL);
    void parseIp(const unsigned char* packet);
    void parseTcp(const unsigned char* l4_start, uint16_t l4_total_len);
    void parseHttp(const char* http_start, uint16_t size);
};


#endif