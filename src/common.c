#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "common.h"

#define NOW uv_default_loop()->time

ping_method_t *ping_method_create(ping_func_t func) {
    ping_method_t *method = malloc(sizeof(ping_method_t));
    if (!method)
        return NULL;
    method->ref_count = 1;
    TAILQ_INIT(&method->wait_queue);
    method->opaque = NULL;
    method->launch_func = func;
    method->kill_func = NULL;
    method->cleanup_func = NULL;
    if (uv_timer_init(uv_default_loop(), &method->timer) < 0) {
        free(method);
        return NULL;
    }
    method->timer.data = method;
    return method;
}

int ping_target_match_dest(ping_target_t *target,
                           struct sockaddr_storage *addr) {
    struct sockaddr_in *dest_in;
    struct sockaddr_in6 *dest_in6;
    if (target->dest.ss_family != addr->ss_family)
        return 0;
    if (addr->ss_family == AF_INET6) {
        dest_in6 = (struct sockaddr_in6 *)&target->dest;
        if (!!memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr,
                     &dest_in6->sin6_addr, sizeof(struct in6_addr)))
            return 0;
    } else {
        dest_in = (struct sockaddr_in *)&target->dest;
        if (!!memcmp(&((struct sockaddr_in *)addr)->sin_addr,
                     &dest_in->sin_addr, sizeof(struct in_addr)))
            return 0;
    }
    return 1;
}

ping_target_t *ping_check_target(ping_method_t *m,
                                 struct sockaddr_storage *addr, int seq_id){
    ping_target_t *iter; //target = ping_lookup_target(&m->wait_queue, addr);
    TAILQ_FOREACH(iter, &m->wait_queue, tq_entry) {
        if (ping_target_match_dest(iter, addr)) {
            if (seq_id != -1 && iter->seq_id != seq_id)
                continue;
            TAILQ_REMOVE(&m->wait_queue, iter, tq_entry);
            iter->last_latency = NOW - iter->last_sched;
            return iter;
        }
    }
    return NULL;
}

ping_method_t *ping_method_retain(ping_method_t *method) {
    method->ref_count++;
    return method;
}

void ping_handler__cleanup(uv_handle_t *handle) {
    free(handle->data);
}

void ping_method_release(ping_method_t *method) {
    if (method->ref_count > 1) {
        method->ref_count--;
        return;
    }
    assert(TAILQ_EMPTY(&method->wait_queue));
    if (method->cleanup_func) {
        method->cleanup_func(method->opaque);
        method->opaque = NULL;
    }
    uv_close((uv_handle_t *)&method->timer, ping_handler__cleanup);
}

static void ping_method__flush_timeout(ping_method_t *method);

static void ping_method__timeout(uv_timer_t* handle) {
    ping_method_t *method = handle->data;
    ping_method__flush_timeout(method);
}

static void ping_method__flush_timeout(ping_method_t *method) {
    uint64_t now = NOW, next_timeout = UINT32_MAX, gap;
    ping_target_t *iter;
    TAILQ_FOREACH(iter, &method->wait_queue, tq_entry) {
        gap = now - iter->last_sched;
        if (gap >= iter->timeout) {
            TAILQ_REMOVE(&method->wait_queue, iter, tq_entry);
            iter->last_state = 0;
            if (iter->method->kill_func)
                iter->method->kill_func(iter, iter->method->opaque);
            ping_schedule_target(iter->owner, iter);
            continue;
        }
        gap = iter->timeout - gap;
        if (gap < next_timeout)
            next_timeout = gap;
    }
    if (!TAILQ_EMPTY(&method->wait_queue))
        uv_timer_start(&method->timer, ping_method__timeout,
                       next_timeout, 0);
}

int ping_parse_addr(const char *addr_str, struct sockaddr_storage *addr) {

    if (uv_inet_pton(AF_INET, addr_str,
                     &((struct sockaddr_in *)addr)->sin_addr) == 0) {
        addr->ss_family = AF_INET;
        return 0;
    }
    else if (uv_inet_pton(AF_INET6, addr_str,
                          &((struct sockaddr_in6 *)addr)->sin6_addr) == 0) {
        addr->ss_family = AF_INET6;
        return 0;
    }
    return -1;
}

ping_target_t *ping_create_target(ping_method_t *method, const char *addr,
                                  int interval, int timeout) {
    ping_target_t *target = malloc(sizeof(ping_target_t));
    if (!target)
        return NULL;
    memset(target, 0, sizeof(*target));
    if (ping_parse_addr(addr, &target->dest) < 0) {
        free(target);
        return NULL;
    }
    target->method = ping_method_retain(method);
    target->last_sched = 0;  /* Causes immediate schedule */
    target->seq_id = -1;
    target->interval = interval;
    target->timeout = timeout;
    return target;
}

void ping_get_target_name(ping_target_t *target, char *out) {
    if (target->dest.ss_family == AF_INET6) {
        uv_inet_ntop(AF_INET6,
                     &((struct sockaddr_in6 *)&target->dest)->sin6_addr,
                     out, 48);
    } else {
        uv_inet_ntop(AF_INET,
                     &((struct sockaddr_in *)&target->dest)->sin_addr,
                     out, 16);
    }
}

void ping_scheduler__flush(ping_scheduler_t *scheduler);

static void ping_scheduler__timeout(uv_timer_t* handle) {
    ping_scheduler_t *scheduler = handle->data;
    ping_scheduler__flush(scheduler);
}

void ping_scheduler__flush(ping_scheduler_t *scheduler) {
    int rv;
    uint64_t now = NOW, next_timeout = UINT32_MAX, gap;
    ping_target_t *iter;
    TAILQ_FOREACH(iter, &scheduler->pend_queue, tq_entry) {
        gap = now - iter->last_sched;
        if (gap < iter->interval) {
            gap = iter->interval - gap;
            if (gap < next_timeout)
                next_timeout = gap;
            continue;
        }
        /* new ping operation should be started */
        iter->last_sched = NOW;
        rv = iter->method->launch_func(iter, iter->method->opaque);
        if (rv < 0) {
            iter->last_state = -2;
            if (next_timeout > iter->interval)
                next_timeout = iter->interval;
            continue;
        }
        /* Move target from pending queue to wait queue */
        TAILQ_REMOVE(&scheduler->pend_queue, iter, tq_entry);
        TAILQ_INSERT_TAIL(&iter->method->wait_queue, iter, tq_entry);
        ping_method__flush_timeout(iter->method);
    }
    if (!TAILQ_EMPTY(&scheduler->pend_queue))
        uv_timer_start(&scheduler->timer, ping_scheduler__timeout,
                       next_timeout, 0);
}

/* Import only `json_object_put` instead of the whole header */
extern int json_object_put(struct json_object *obj);

int ping_destroy_target(ping_target_t *target) {
    ping_target_t *iter;
    if (target->owner) {
        TAILQ_FOREACH(iter, &target->method->wait_queue, tq_entry) {
            if (iter == target) {
                TAILQ_REMOVE(&target->method->wait_queue, iter, tq_entry);
                ping_method__flush_timeout(target->method);
                if (target->method->kill_func)
                    target->method->kill_func(target, target->method->opaque);
                /* After ping_method__flush_timeout, iteration should stop */
                break;
            }
        }
        TAILQ_FOREACH(iter, &target->owner->pend_queue, tq_entry) {
            if (iter == target) {
                TAILQ_REMOVE(&target->owner->pend_queue, iter, tq_entry);
                break;
            }
        }
        target->owner = NULL;
    }
    if (target->report)
        json_object_put(target->report);
    free(target);
    return 0;
}

ping_scheduler_t *ping_create_scheduler() {
    ping_scheduler_t *scheduler = malloc(sizeof(ping_scheduler_t));
    int rv;
    if (!scheduler)
        return NULL;
    TAILQ_INIT(&scheduler->pend_queue);
    rv = uv_timer_init(uv_default_loop(), &scheduler->timer);
    if (rv < 0) {
        free(scheduler);
        return NULL;
    }
    scheduler->timer.data = scheduler;
    return scheduler;
}

int ping_schedule_target(ping_scheduler_t *scheduler, ping_target_t *target) {
    target->owner = scheduler;
    TAILQ_INSERT_TAIL(&scheduler->pend_queue, target, tq_entry);
    uv_timer_start(&scheduler->timer, ping_scheduler__timeout,
                   1, 0);
    return 0;
}

void ping_teardown_scheduler(ping_scheduler_t *scheduler) {
    uv_close((uv_handle_t *)&scheduler->timer, ping_handler__cleanup);
}