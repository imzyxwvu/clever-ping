#include <stdlib.h>
#include <string.h>
#include <http_parser.h>
#include <json.h>
#include "common.h"

struct ping_service_s {
    ping_scheduler_t *scheduler;
    ping_target_head_t targets;
    int session_count;
    union {
        uv_stream_t api_server;
        uv_tcp_t api_server_tcp;
    };
};

typedef struct api_session_s {
    ping_service_t *service;
    union {
        uv_stream_t api_session;
        uv_tcp_t api_session_tcp;
    };
    http_parser parser;
    struct json_tokener *tokener;
    struct json_object *data;
    char url[0x200];
    char http_buffer[0x1000];
    uv_write_t write_req;
} api_session_t;

static struct http_parser_settings http_parser_cbs;

#define RESPONSE_TAIL "Connection: close\r\nContent-Length: 0\r\n\r\n"
static const char http_response__200[] =
        "HTTP/1.1 200 OK\r\n" RESPONSE_TAIL;
static const char http_response__400[] =
        "HTTP/1.1 400 Bad Request\r\n" RESPONSE_TAIL;
static const char http_response__404[] =
        "HTTP/1.1 404 Not Found\r\n" RESPONSE_TAIL;
static const char http_response__405[] =
        "HTTP/1.1 405 Method Not Allowed\r\n" RESPONSE_TAIL;
static const char http_response__500[] =
        "HTTP/1.1 500 Internal Server Error\r\n" RESPONSE_TAIL;

static void ping_service__post_destroy(uv_handle_t *handle) {
    ping_service_t *service = handle->data;
    if (service->scheduler)
        ping_teardown_scheduler(service->scheduler);
    free(service);
}

void ping_service_destroy(ping_service_t *service) {
    uv_close((uv_handle_t *)&service->api_server,
             ping_service__post_destroy);
}

static void api_session__post_destroy(uv_handle_t *handle) {
    free(handle->data);
}

static void api_session_destroy(api_session_t *session) {
    if (session->data) {
        json_object_put(session->data);
        session->data = NULL;
    }
    if (session->tokener) {
        json_tokener_free(session->tokener);
        session->tokener = NULL;
    }
    if (session->service) {
        session->service->session_count--;
        session->service = NULL;
    }
    uv_close((uv_handle_t *)&session->api_session_tcp,
             api_session__post_destroy);
}

static void api_session__alloc_cb(uv_handle_t* handle,
                                  size_t suggested_size, uv_buf_t* buf) {
    api_session_t *session = handle->data;
    buf->base = session->http_buffer;
    buf->len = sizeof(session->http_buffer);
}

static void api_session__read_cb(uv_stream_t* stream,
                                 ssize_t nread, const uv_buf_t* buf) {
    api_session_t *session = stream->data;
    size_t n_parsed;
    if (nread < 0) {
        if (nread != UV_EOF)
            api_session_destroy(session);
        return;
    }
    n_parsed = http_parser_execute(&session->parser, &http_parser_cbs,
                                   buf->base, nread);
    if ((int)session->parser.upgrade || n_parsed < nread)
        api_session_destroy(session);
}

static void ping_service__accept_api(uv_stream_t* server, int status) {
    api_session_t *session;
    session = malloc(sizeof(api_session_t));
    if (!session)
        return;
    memset(session, 0, sizeof(*session));
    if (uv_tcp_init(uv_default_loop(), &session->api_session_tcp) < 0) {
        free(session);
        return;
    }
    session->api_session_tcp.data = session;
    http_parser_init(&session->parser, HTTP_REQUEST);
    session->parser.data = session;
    session->write_req.data = session;
    if (uv_accept(server, &session->api_session) < 0) {
        api_session_destroy(session);
        return;
    }
    if (uv_read_start(&session->api_session,
                      api_session__alloc_cb, api_session__read_cb) < 0)
        api_session_destroy(session);
    /* Retain ping_service_t reference */
    session->service = server->data;
    session->service->session_count++;
}

static int safe_strncat(char *dest, size_t max, const char *src, size_t len) {
    size_t ins_pos = strlen(dest);
    if (max - (ins_pos + 1) < len)
        return -1;
    memcpy(dest + ins_pos, src, len);
    return 0;
}

static int api_session__append_url(http_parser *parser,
                                   const char *at, size_t length) {
    api_session_t *session = parser->data;
    return safe_strncat(session->url, sizeof(session->url), at, length);
}

static int api_session__json_prepare(http_parser *parser) {
    api_session_t *session = parser->data;
    if (parser->method == HTTP_POST) {
        session->tokener = json_tokener_new();
        if (!session->tokener)
            return -1;
    }
    return 0;
}

static int api_session__append_body(http_parser *parser,
                                    const char *at, size_t length) {
    api_session_t *session = parser->data;
    if (!session->tokener || session->data)
        return 0;
    session->data = json_tokener_parse_ex(session->tokener, at, length);
    if (session->data) {
        json_tokener_free(session->tokener);
        session->tokener = NULL;
    }
    return 0;
}

static void api_session__write_completed(uv_write_t *req, int status) {
    api_session_t *session = req->data;
    if (!uv_is_closing((uv_handle_t *)req->handle))
        api_session_destroy(session);
}

static int api_remove_target(ping_service_t *service, const char *name) {
    struct sockaddr_storage dest;
    ping_target_t *iter = TAILQ_FIRST(&service->targets), *next;
    int rv;
    if (strchr(name, ':')) {
        rv = uv_ip6_addr(name, 0, (struct sockaddr_in6 *)&dest);
    } else {
        rv = uv_ip4_addr(name, 0, (struct sockaddr_in *)&dest);
    }
    if (rv < 0)
        return -1;
    /* Iterate targets with different methods */
    rv = -1;
    while (iter) {
        if (ping_target_match_dest(iter, &dest)) {
            next = TAILQ_NEXT(iter, gq_entry);
            TAILQ_REMOVE(&service->targets, iter, gq_entry);
            ping_destroy_target(iter);
            rv = 0;
        }
        iter = TAILQ_NEXT(iter, gq_entry);
    }
    return rv;
}

int api_setup_target(ping_service_t *service,
                     const char *name, struct json_object *spec) {
    ping_target_t *target;
    json_object *val;
    int interval = 1000, timeout = 500;
    /* Override with user-specified parameters */
    if ((val = json_object_object_get(spec, "interval")))
        interval = json_object_get_int(val);
    if ((val = json_object_object_get(spec, "timeout")))
        timeout = json_object_get_int(val);
    if (timeout > interval)
        timeout = interval;  /* Adjust */
    target = icmp_ping_create_target(name, interval, timeout);
    if (!target)
        return -1;
    api_remove_target(service, name);
    TAILQ_INSERT_TAIL(&service->targets, target, gq_entry);
    ping_schedule_target(service->scheduler, target);
    return 0;
}

static int api_session__handle_post(api_session_t *session) {
    json_object_object_foreach(session->data, target_name, spec) {
        if (json_object_get_type(spec) != json_type_object)
            return -1;
        if (api_setup_target(session->service, target_name, spec) < 0)
            return -1;
    }
    return 0;
}

static const char *api_get_state_desc(ping_target_t *state) {
    switch (state->last_state) {
        case -2: return "error";
        case -1: return "unreach";
        case 0: return "timeout";
        case 1: return "ok";
        default: return "unknown";
    }
}

static int api_session__list_targets(api_session_t *session) {
    ping_target_t *iter;
    char name[48];
    if (session->data)
        json_object_put(session->data);
    session->data = json_object_new_object();
    if (!session->data)
        return -1;
    TAILQ_FOREACH(iter, &session->service->targets, gq_entry) {
        json_object *obj;
        ping_get_target_name(iter, name);
        obj = json_object_object_get(session->data, name);
        if (!obj) {
            obj = json_object_new_object();
            json_object_object_add(session->data, name, obj);
        }
        if (iter->report) {
            json_object_object_foreach(obj, field, val) {
                /* Copy to response object */
                json_object_object_add(obj, field, json_object_get(val));
            }
        } else {
            json_object_object_add(obj, "state",
                json_object_new_string(api_get_state_desc(iter)));
            json_object_object_add(obj, "latency",
                json_object_new_int(iter->last_latency));
        }
    }
    return 0;
}

static int api_session__render_json(api_session_t *session) {
    uv_buf_t buf[2];
    buf[1].base = (char *)
            json_object_to_json_string_length(session->data,
                                              0, &buf[1].len);
    if (!buf[1].base)
        return 500;
    buf[0].base = session->http_buffer;
    buf[0].len = sprintf(
            session->http_buffer,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: %ld\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n\r\n",
            buf[1].len);
    if (uv_write(&session->write_req, &session->api_session,
                 buf, 2, api_session__write_completed) < 0)
        api_session_destroy(session);
    return 0;
}

static int api_session__dispatch(api_session_t *session,
                                 unsigned int method) {
    char *query_begin;
    if (session->tokener)  /* check for incomplete JSON */
        return 400;
    query_begin = strchr(session->url, '?');
    if (query_begin)
        *query_begin = 0;  /* Remove query string */
    if (strcmp(session->url, "/tgt") == 0) {
        switch (method) {
        case HTTP_GET:
            if (api_session__list_targets(session) < 0)
                return 500;
            return api_session__render_json(session);
        case HTTP_POST:
            if (json_object_get_type(session->data)
                    != json_type_object)
                return 400;
            if (api_session__handle_post(session) < 0)
                return 500;
            return 200;
        default:
            return 405;
        }
    }
    else if (memcmp(session->url, "/tgt/", 5) == 0) {
        switch (method) {
        case HTTP_GET:
            return 405;
        case HTTP_DELETE:
            if (api_remove_target(session->service,
                                  session->url + 5) < 0)
                return 404;  /* Illegal address */
            return 200;
        default:
            return 405;
        }
    }
    return 404;
}

static int api_session__handle_request(http_parser *parser) {
    api_session_t *session = parser->data;
    uv_buf_t buf;
    /* session->http_buffer will be available */
    uv_read_stop(&session->api_session);
    parser->status_code =
            api_session__dispatch(session, parser->method);
    switch ((int)parser->status_code) {
    case 200:
        buf.base = (char *)http_response__200;
        buf.len = sizeof(http_response__200) - 1;
        break;
    case 400:
        buf.base = (char *)http_response__400;
        buf.len = sizeof(http_response__400) - 1;
        break;
    case 404:
        buf.base = (char *)http_response__404;
        buf.len = sizeof(http_response__404) - 1;
        break;
    case 405:
        buf.base = (char *)http_response__405;
        buf.len = sizeof(http_response__405) - 1;
        break;
    case 500:
        buf.base = (char *)http_response__500;
        buf.len = sizeof(http_response__500) - 1;
        break;
    default:
        return 0;
    }
    if (uv_write(&session->write_req, &session->api_session,
                 &buf, 1, api_session__write_completed) < 0)
        api_session_destroy(session);
    return 0;
}

ping_service_t *ping_service_create(struct sockaddr *bind_addr) {
    ping_service_t *service = malloc(sizeof(ping_service_t));
    int rv;
    if (!service)
        return NULL;
    memset(service, 0, sizeof(*service));
    TAILQ_INIT(&service->targets);
    service->scheduler = ping_create_scheduler();
    if (!service->scheduler) {
        free(service);
        return NULL;
    }
    if (uv_tcp_init(uv_default_loop(),
                    &service->api_server_tcp) < 0) {
        free(service);
        return NULL;
    }
    service->api_server.data = service;
    /* Prepare http_parser_cbs */
    memset(&http_parser_cbs, 0, sizeof(http_parser_cbs));
    http_parser_cbs.on_url = api_session__append_url;
    http_parser_cbs.on_headers_complete = api_session__json_prepare;
    http_parser_cbs.on_body = api_session__append_body;
    http_parser_cbs.on_message_complete = api_session__handle_request;
    /* Start API connection listener */
    rv = uv_tcp_bind(&service->api_server_tcp, bind_addr, 0);
    if (rv < 0) {
        fprintf(stderr, "Bind API address: %s\n", uv_strerror(rv));
        ping_service_destroy(service);
        return NULL;
    }
    rv = uv_listen(&service->api_server, 8, ping_service__accept_api);
    if (rv < 0) {
        ping_service_destroy(service);
        return NULL;
    }
    return service;
}
