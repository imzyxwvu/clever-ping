#ifndef CLEVER_PING_COMMON_H
#define CLEVER_PING_COMMON_H

#include <uv.h>
#include <sys/queue.h>
#include <arpa/inet.h>


typedef struct ping_target_s ping_target_t;
typedef TAILQ_HEAD(ping_target_head_s, ping_target_s) ping_target_head_t;

typedef int (*ping_func_t)(struct ping_target_s *tgt, void *opaque);
typedef void (*ping_cleanup_func_t)(void *opaque);

typedef struct ping_method_s {
    ping_func_t launch_func, kill_func;
    ping_cleanup_func_t cleanup_func;
    ping_target_head_t wait_queue;
    int ref_count;
    void *opaque;
    uv_timer_t timer;
} ping_method_t;

struct ping_target_s {
    struct sockaddr_storage dest;
    int interval, timeout;
    uint64_t last_sched;
    ping_method_t *method;
    struct json_object *report;
    int last_state, last_latency, seq_id;
    TAILQ_ENTRY(ping_target_s) tq_entry, gq_entry;
    struct ping_scheduler_s *owner;
};

typedef struct ping_scheduler_s {
    ping_target_head_t pend_queue;
    uv_timer_t timer;
} ping_scheduler_t;


ping_method_t *ping_method_create(ping_func_t launch_func);
ping_target_t *ping_check_target(ping_method_t *m,
                                 struct sockaddr_storage *addr, int seq_id);
ping_method_t *ping_method_retain(ping_method_t *m);
void ping_method_release(ping_method_t *m);

ping_target_t *ping_create_target(ping_method_t *method, const char *addr,
                                  int interval, int timeout);
void ping_get_target_name(ping_target_t *target, char *out);
int ping_target_match_dest(ping_target_t *target,
                           struct sockaddr_storage *addr);
int ping_destroy_target(ping_target_t *target);

ping_scheduler_t *ping_create_scheduler();
int ping_schedule_target(ping_scheduler_t *scheduler, ping_target_t *target);
void ping_teardown_scheduler(ping_scheduler_t *);

ping_target_t *icmp_ping_create_target(const char *addr,
                                       int interval, int timeout);

typedef struct ping_service_s ping_service_t;

ping_service_t *ping_service_create(struct sockaddr *bind_addr);
int api_setup_target(ping_service_t *service,
                     const char *name, struct json_object *spec);
void ping_service_destroy(ping_service_t *service);

#endif //CLEVER_PING_COMMON_H
