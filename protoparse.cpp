#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>
#include <unordered_map>

#include "protoparse.h"

using namespace std;

L7Parser::L7Parser(const unsigned char* _packet) {
    if (_packet != NULL) {
        packet = _packet;
        parseIp(packet);
        if (l4_proto == IPPROTO_TCP) {
            parseTcp(l4_start, l4_total_len);
        }
        if (l7_proto == L7Proto::HTTP) {
            try {
                parseHttp(l7_start, l7_total_len);
            } catch (const char *e) {
                fprintf(stderr, "[ERROR] %s\n", e);
            }
        }
    }
}


void L7Parser::parseIp(const unsigned char* _packet) {
    ip_hdr = (struct ip*)_packet;
    // printf("    src IP   : %s\n", inet_ntoa(ip_hdr->ip_src));
    // printf("    dst IP   : %s\n", inet_ntoa(ip_hdr->ip_dst));
    
    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP:
            {
            l4_proto = IPPROTO_TCP;
            // caculate header length : 4bit(& 0xF) and * word(4)
            ip_hdr_len = (ip_hdr->ip_hl & 0xF) * 4;
            // total length - header length = next protocol lenth
            l4_total_len = htons(ip_hdr->ip_len) - ip_hdr_len;
            l4_start = _packet + ip_hdr_len;
            break;
            }
        default:
            // printf("Upper proto is not TCP / Protocol : %u\n", ip_hdr->ip_p);
            l4_proto = -1;
            break;
    }
}
void L7Parser::parseTcp(const unsigned char* tcp_start, uint16_t tcp_total_len) {
    struct tcphdr* tcp_hdr = (struct tcphdr*)tcp_start;
    // printf("    src port : %hu\n", htons(tcp_hdr->th_sport));
    // printf("    dst port : %hu\n", htons(tcp_hdr->th_dport));

    // caculate payload lenth
    uint8_t tcp_hdr_len = ((tcp_hdr->th_off & 0xF) * 4);
    l7_start = (const char*)tcp_start + tcp_hdr_len;
    l7_total_len = tcp_total_len - tcp_hdr_len;

    const char* payload = l7_start;
    uint16_t payload_len = l7_total_len;

    // printf("    payload length : %hu\n", payload_len);
    // if (payload_len > 0) {
    //     printf("    DATA : ");
    //     int print_len = (16 < payload_len) ? 16 : payload_len;
    //     for (int i = 0; i < print_len; i++) {
    //         printf("%c", payload[i]);
    //     }
    //     puts("");
    // }

    // GET .*? HTTP/.*
    if (l7_total_len > 3 && (!memcmp(l7_start, "GET", 3) || !memcmp(l7_start, "POST", 3))) {
        l7_proto = L7Proto::HTTP;
    }
    else {
        l7_proto = L7Proto::NONE;
    }
}

void L7Parser::parseHttp(const char* http_start, uint16_t size) {
    /* However some servers might omit the \r and only send \n lines, 
    particularly if they fail to sanitise any CGI supplied headers to ensure that they include the \r.
    */
    const char *EOH_STR = "\r\n\r\n";
    char *hdr_end = strstr((char*)http_start, EOH_STR);
    if (hdr_end == NULL) {
        throw "this doesn't contain EOH_STR";
    }

    size_t hdr_size = hdr_end - http_start;
    string hdr_str(http_start, hdr_size);
    istringstream hdr_stream(hdr_str);
    string start_line, item;
    if (!getline(hdr_stream, start_line)) {
        throw "[ERROR] start_line";
    }
    // cout << "[STLINE]" << start_line << '\n';
    while (getline(hdr_stream, item)) {
        // cout << "[ITEM]" << item << '\n';
        auto pos = item.find(':');
        string key = item.substr(0, pos);
        string value = item.substr(pos+2, item.length() - (pos + 2) - 1);
        http_hdr.insert(make_pair(key, value));
        // cout << http_hdr[key] << endl;
        // cout << http_hdr[key].length() << endl;
    }
}


