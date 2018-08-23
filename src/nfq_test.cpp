#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <fstream>

#include "protoparse.h"

std::unordered_map<std::string, int> mal_url_list;
static bool isContainMalHost(struct nfq_data *tb, u_int32_t *id) {
    unsigned char *data;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        *id = ntohl(ph->packet_id);
        // printf("hw_protocol=0x%04x hook=%u id=%u ",
            // ntohs(ph->hw_protocol), ph->hook, *id);
    }

    int ret;
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        L7Parser p(data);
        if (p.http_hdr.count("Host")) { // if exist && p.http_hdr["Host"] contain...
            std::cout << "[HOST]" << p.http_hdr["Host"] << '\n';
            // auto item = mal_url_list.find(p.http_hdr["Host"]);
            // if (item != mal_url_list.end()) {
                // return true;
            // }
            if (mal_url_list.count(p.http_hdr["Host"])) {
                return true;
            }
        }
    }
    return false;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    // id = print_pkt(nfa);
    bool tf = isContainMalHost(nfa, &id);
    if (tf) {
        printf("[*] Contain Malicious Host. NF_DROP\n");
    }
    return nfq_set_verdict(qh, id, tf ? NF_DROP : NF_ACCEPT, 0, NULL);
}

void fillHashMapFromFile(const char *fname) {
    const int USER_BUFSIZ = 1024*128;   // 128K
    const int MAX_URL_LEN = 512;
    std::ifstream ifs;
    char buf[USER_BUFSIZ];
    ifs.rdbuf()->pubsetbuf(buf, USER_BUFSIZ);
    ifs.open(fname);
    if (ifs.fail()) {
        std::cout << "[*] failed to open" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    std::string url;
    while (!ifs.eof()) {
        std::getline(ifs, url);
        size_t pos = url.find(',');
        // std::cout << url.substr(pos+1) << '\n';
        mal_url_list.insert(make_pair(url.substr(pos+1), 0));
    }
    ifs.close();
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        printf("usage : %s <mal_list_file_name>\n", argv[0]);
        return -1;
    }
    const char *mal_list_fname = argv[1];

    ////////////////////////////////////////////////////////////
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    fd = nfq_fd(h);
    ////////////////////////////////////////////////////////////
    printf("[*] Read %s and fill hash_map\n", mal_list_fname);
    fillHashMapFromFile(mal_list_fname);
    printf("[*] Done.\n");
    ////////////////////////////////////////////////////////////
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            // printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);


    exit(0);
}

