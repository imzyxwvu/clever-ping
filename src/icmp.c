#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "common.h"

typedef struct ping_method_icmp_s {
    unsigned int id;
    int fd;
    uv_poll_t poll;
    ping_method_t *method;
    uint8_t buf[0x8000];
} ping_method_icmp_t;

typedef struct icmp_header_s {
    uint8_t type, code;
    uint16_t checksum, id, seq;
} icmp_header_t;

#define ICMP6_TYPE_REPLY 129

static ping_method_t *singleton_icmp = NULL;
static ping_method_t *singleton_icmp6 = NULL;
static const char fill_pattern[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                                   "abcdefghijklmnopqrstuvwxyz";

static unsigned short icmp_ping__calc_checksum(void *addr, int left)
{
    unsigned int sum = 0;
    unsigned short *w = addr;
    while (left > 1) {
        sum += *w++;
        left -= 2;
    }
    if (left == 1)
        sum += *(unsigned char *)w;
    sum = (sum >> 16u) + (sum & 0xffffu);
    sum += (sum >> 16u);
    return ~sum;
}

static void icmp_ping__decode(ping_method_icmp_t *icmp, int avail,
                              struct sockaddr_storage *from) {
    icmp_header_t *header;
    ping_target_t *target = NULL;
    unsigned int ip_hl = (icmp->buf[0] & 0xfu) << 2u;
    uint8_t *icmp_base;
    uint8_t ttl = icmp->buf[8];
    char name[64];
    if (avail < ip_hl + sizeof(icmp_header_t))
        return;
    icmp_base = icmp->buf + ip_hl;
    header = (icmp_header_t *)icmp_base;
    if (header->type == 0 && header->code == 0 && ntohs(header->id) == icmp->id)
        target = ping_check_target(icmp->method, from, ntohs(header->seq));
    /* Check for ICMP errors */
    else if ((header->type == 3 || header->type == 11) &&
        avail > ip_hl + sizeof(icmp_header_t) + 20 && icmp_base[17] == IPPROTO_ICMP) {
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        memcpy(&dest.sin_addr, icmp_base + 24, sizeof(dest.sin_addr));
        target = ping_check_target(icmp->method,
                                   (struct sockaddr_storage *)&dest, -1);
    }
    if (!target)
        return;
    target->last_state = header->type == 0 ? 1 : -1;
    ping_get_target_name(target, name);
    ping_schedule_target(target->owner, target); /* Continue */
}

static void icmp6_ping__decode(ping_method_icmp_t *icmp, int avail,
                               struct sockaddr_storage *from) {
    icmp_header_t *header;
    ping_target_t *target = NULL;
    char name[64];
    if (avail < sizeof(icmp_header_t))
        return;
    header = (icmp_header_t *)icmp->buf;
    if (header->type == ICMP6_TYPE_REPLY && header->code == 0 &&
        ntohs(header->id) == icmp->id)
        target = ping_check_target(icmp->method, from, ntohs(header->seq));
    /* Check for ICMPv6 errors */
    else if ((header->type == 1 || header->type == 3) &&
             avail > 40 + sizeof(icmp_header_t) && icmp->buf[14] == IPPROTO_ICMPV6) {
        struct sockaddr_in6 dest;
        dest.sin6_family = AF_INET6;
        memcpy(&dest.sin6_addr, icmp->buf + 32, sizeof(dest.sin6_addr));
        target = ping_check_target(icmp->method,
                                   (struct sockaddr_storage *)&dest, -1);
    }
    if (!target)
        return;
    target->last_state = header->type == ICMP6_TYPE_REPLY ? 1 : -1;
    ping_get_target_name(target, name);
    ping_schedule_target(target->owner, target); /* Continue */
}

static void icmp_ping__check(uv_poll_t *poll, int status, int events) {
    ping_method_icmp_t *icmp = poll->data;
    int n_bytes;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    if (status < 0)
        return;
    while (1) {
        addr_len = sizeof(addr);
        n_bytes = recvfrom(icmp->fd, icmp->buf, sizeof(icmp->buf),
                           MSG_DONTWAIT,
                           (struct sockaddr *)&addr, &addr_len);
        if (n_bytes == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
        }
        if (n_bytes < 20 + sizeof(struct icmp_header_s))
            continue;
        if (addr.ss_family == AF_INET)
            icmp_ping__decode(icmp, n_bytes, &addr);
        else if (addr.ss_family == AF_INET6)
            icmp6_ping__decode(icmp, n_bytes, &addr);
    }
}

static void icmp_ping__build_message(ping_method_icmp_t *icmp,
                                     ping_target_t *target, int n_bytes)
{
    struct icmp_header_s *header = (struct icmp_header_s *)&icmp->buf;
    /* ECHO request type is 8 in ICMP, or 128 in ICMPv6 */
    header->type = (target->dest.ss_family == AF_INET6 ? 128 : 8);
    header->code = 0;
    header->checksum = 0;
    header->id = htons(icmp->id);
    header->seq = htons(++target->seq_id);
    /* Fill rest with pattern */
    memcpy((char *)icmp->buf + sizeof(*header),
           fill_pattern, n_bytes - sizeof(*header));
    header->checksum = icmp_ping__calc_checksum(&icmp->buf, n_bytes);
}

static int icmp_ping_launch(ping_target_t *target, void *opaque) {
    ping_method_icmp_t *icmp = opaque;
    int n_bytes = 64, rv;
    /* Take care of fill_pattern while selecting greater length */
    icmp_ping__build_message(icmp, target, n_bytes);
    rv = sendto(icmp->fd, icmp->buf, n_bytes, 0,
                (struct sockaddr *)&target->dest, sizeof(target->dest));
    if (rv == -1) {
        perror("icmp_ping_launch(sendto)");
        return -1;
    }
    rv = uv_poll_start(&icmp->poll, UV_READABLE, icmp_ping__check);
    return rv < 0 ? -1 : 0;
}

static void icmp_ping__post_cleanup(uv_handle_t *handle) {
    ping_method_icmp_t *icmp = handle->data;
    close(icmp->fd);
    free(icmp);
}

static void icmp_ping_cleanup(void *opaque) {
    ping_method_icmp_t *icmp = opaque;
    if (icmp->method == singleton_icmp)
        singleton_icmp = NULL;  /* Break singleton reference */
    if (icmp->fd == -1) {
        free(icmp);
        return;
    }
    icmp->method = NULL;
    uv_close((uv_handle_t *)&icmp->poll, icmp_ping__post_cleanup);
}

static ping_method_t *icmp_ping_create(int addr_family) {
    ping_method_icmp_t *icmp;
    ping_method_t *method = ping_method_create(icmp_ping_launch);
    if (!method)
        return NULL;
    icmp = malloc(sizeof(ping_method_icmp_t));
    if (!icmp) {
        ping_method_release(method);
        return NULL;
    }
    method->opaque = icmp;
    method->cleanup_func = icmp_ping_cleanup;
    if (addr_family == AF_INET6) {
        icmp->fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    } else {
        icmp->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (icmp->fd == -1) {
        perror("icmp_ping_create(socket)");
        ping_method_release(method);
        return NULL;
    }
    if(uv_poll_init(uv_default_loop(), &icmp->poll, icmp->fd) < 0) {
        close(icmp->fd);
        icmp->fd = -1;
        ping_method_release(method);
        return NULL;
    }
    icmp->poll.data = icmp;
    icmp->method = method;
    icmp->id = rand() % 0x10000;
    return method;
}

ping_method_t *icmp_ping_get() {
    if (singleton_icmp)
        return ping_method_retain(singleton_icmp);
    singleton_icmp = icmp_ping_create(AF_INET);
    return singleton_icmp;
}

ping_method_t *icmp6_ping_get() {
    if (singleton_icmp6)
        return ping_method_retain(singleton_icmp6);
    singleton_icmp6 = icmp_ping_create(AF_INET6);
    return singleton_icmp6;
}

ping_target_t *icmp_ping_create_target(const char *addr,
                                       int interval, int timeout) {
    ping_method_t *method;
    ping_target_t *target;
    if (strchr(addr, ':')) {
        method = icmp6_ping_get();
    } else {
        method = icmp_ping_get();
    }
    if (!method)
        return NULL;
    target = ping_create_target(method, addr, interval, timeout);
    ping_method_release(method);
    return target;
}