#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <time.h>

#include <string>
#include <unordered_set>
#include <fstream>
#include <iostream>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

unordered_set<string> bad_hosts;

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        if (hlen > 0) {
            printf("hw_src_addr=");
            for (i = 0; i < hlen - 1; i++)
                printf("%02x:", hwph->hw_addr[i]);
            printf("%02x ", hwph->hw_addr[hlen - 1]);
        }
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);

    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    int verdict = NF_ACCEPT;

    unsigned char *pkt;
    int len;

    len = nfq_get_payload(nfa, &pkt);
    if (len < 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    if (len < 20)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    unsigned char ip_version = pkt[0] >> 4;
    unsigned char ip_ihl = pkt[0] & 0x0f;
    int ip_hlen = ip_ihl * 4;

    if (ip_version != 4)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    if (ip_hlen < 20)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    if (len < ip_hlen)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    if (pkt[9] != 6)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    unsigned char *tcp = pkt + ip_hlen;

    if (len < ip_hlen + 20)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    unsigned short sport = (tcp[0] << 8) | tcp[1];
    unsigned short dport = (tcp[2] << 8) | tcp[3];

    int tcp_hlen = ((tcp[12] >> 4) & 0x0f) * 4;

    if (tcp_hlen < 20)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    if (len < ip_hlen + tcp_hlen)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    unsigned char *http = pkt + ip_hlen + tcp_hlen;
    int http_len = len - ip_hlen - tcp_hlen;

    if (http_len <= 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    if (!((http_len >= 4 && !memcmp(http, "GET ", 4)) || (http_len >= 5 && !memcmp(http, "POST ", 5)) || (http_len >= 5 && !memcmp(http, "HEAD ", 5)) || (http_len >= 4 && !memcmp(http, "PUT ", 4)) || (http_len >= 7 && !memcmp(http, "DELETE ", 7)) || (http_len >= 8 && !memcmp(http, "OPTIONS ", 8)) || (http_len >= 6 && !memcmp(http, "PATCH ", 6)))) 
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
 
    printf("[TCP] %u -> %u\n", sport, dport);

    char host[256] = {0};

    for (int i = 0; i < http_len - 5; i++) 
    {
        if (!strncasecmp((char *)http + i, "Host:", 5)) 
        {
            int j = i + 5;
            int k = 0;

            while (j < http_len && (http[j] == ' ' || http[j] == '\t'))
                j++;

            while (j < http_len && http[j] != '\r' && http[j] != '\n' && http[j] != ':' && k < 255) 
            {
                if ('A' <= http[j] && http[j] <= 'Z')
                    host[k++] = http[j] + 32;
                else
                    host[k++] = http[j];
                j++;
            }

            host[k] = '\0';
            break;
        }
    }

    if (host[0]) 
    {
        struct timespec search_s, search_e;
        long search_diff_ns;

        printf("[HTTP] Host: %s\n", host);

        clock_gettime(CLOCK_MONOTONIC, &search_s);

        if (bad_hosts.find(host) != bad_hosts.end())
            verdict = NF_DROP;

        clock_gettime(CLOCK_MONOTONIC, &search_e);

        search_diff_ns = (search_e.tv_sec - search_s.tv_sec) * 1000000000L + (search_e.tv_nsec - search_s.tv_nsec);

        printf("[SEARCH] host=%s time=%ld ns\n", host, search_diff_ns);

        if (verdict == NF_DROP)
            printf("[DROP] blocked host: %s\n", host);
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    struct timespec load_s, load_e;
    long load_diff_ms;

    if (argc != 2) {
        fprintf(stderr, "syntax : %s <site list file>\n", argv[0]);
        fprintf(stderr, "sample : %s top-1m.csv\n", argv[0]);
        exit(1);
    }

    clock_gettime(CLOCK_MONOTONIC, &load_s);

    ifstream file(argv[1]);
    if (!file.is_open()) {
        perror("file open");
        exit(1);
    }

    bad_hosts.reserve(2000000);

    string line;

    while (getline(file, line)) 
    {
        size_t comma;
        string host;

        if (!line.empty() && line[line.length() - 1] == '\r')
            line.erase(line.length() - 1);

        comma = line.find(',');
        if (comma == string::npos)
            continue;

        host = line.substr(comma + 1);

        if (host.empty())
            continue;

        for (int i = 0; i < (int)host.length(); i++) 
        {
            if ('A' <= host[i] && host[i] <= 'Z')
                host[i] += 32;
        }

        bad_hosts.insert(host);
    }

    file.close();

    clock_gettime(CLOCK_MONOTONIC, &load_e);

    load_diff_ms = (load_e.tv_sec - load_s.tv_sec) * 1000 + (load_e.tv_nsec - load_s.tv_nsec) / 1000000;

    printf("[LOAD] blocked site count: %lu\n", bad_hosts.size());
    printf("[LOAD] load time: %ld ms\n", load_diff_ms);

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
    qh = nfq_create_queue(h, 0, &cb, NULL);
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

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }

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
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}