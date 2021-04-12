#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <json.h>
#include "common.h"

struct init_options_s {
    char bind_address[48];
    int bind_port;
    char init_config[PATH_MAX];
} init_options;

struct json_object *load_json_file(const char *path)
{
    json_tokener *tok = json_tokener_new();
    json_object *obj;
    FILE *fp;
    char read_buf[4096];
    size_t n_read;
    if (!tok)
        return NULL;
    fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to load initial target list");
        json_tokener_free(tok);
        return NULL;
    }
    while((n_read = fread(read_buf, 1, sizeof(read_buf), fp))) {
        obj = json_tokener_parse_ex(tok, read_buf, n_read);
        if (obj || json_tokener_get_error(tok) != json_tokener_continue)
            break;
    }
    fclose(fp);
    if (!obj) {
        enum json_tokener_error err = json_tokener_get_error(tok);
        if (err == json_tokener_success) {
            fprintf(stderr, "JSON parse failed: truncated file\n");
        } else {
            fprintf(stderr, "JSON parse failed: %s\n",
                    json_tokener_error_desc(err));
        }
    }
    json_tokener_free(tok);
    return obj;
}

static void load_dest_list(ping_service_t *service, json_object *data) {
    json_object_object_foreach(data, target_name, spec) {
        if (json_object_get_type(spec) != json_type_object)
            continue;
        if (api_setup_target(service, target_name, spec) < 0)
            fprintf(stderr, "Warning: target %s is not loaded.\n",
                    target_name);
    }
}

static int load_init_config(ping_service_t *service, const char *path)
{
    struct json_object *obj = load_json_file(path);
    if (!obj)
        return -1;
    if (json_object_get_type(obj) != json_type_object) {
        fprintf(stderr, "JSON parse failed: object expected\n");
        json_object_put(obj);
        return -1;
    }
    load_dest_list(service, obj);
    json_object_put(obj);
    return 0;
}

int run_service(struct init_options_s *opts) {
    struct sockaddr_storage bind_addr;
    ping_service_t *service;
    if (strchr(opts->bind_address, ':')) {
        uv_ip6_addr(opts->bind_address, opts->bind_port,
                    (struct sockaddr_in6 *)&bind_addr);
    } else {
        uv_ip4_addr(opts->bind_address, opts->bind_port,
                    (struct sockaddr_in *)&bind_addr);
    }
    service = ping_service_create((struct sockaddr *) &bind_addr);
    if (opts->init_config[0]) {
        /* Load initial ping targets */
        if (load_init_config(service, opts->init_config) < 0) {
            ping_service_destroy(service);
            return EXIT_FAILURE;
        }
    }
    if (!service)
        return EXIT_FAILURE;
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    ping_service_destroy(service);
    return 0;
}

int main(int argc, char *argv[]) {
    struct init_options_s opts;
    int opt;
    strcpy(opts.bind_address, "0.0.0.0");
    opts.bind_port = 8001;
    strcpy(opts.init_config, "");
    while ((opt = getopt(argc, argv, "b:p:i:")) != -1) {
        switch (opt) {
        case 'b':
            strcpy(opts.bind_address, optarg);
            break;
        case 'p':
            opts.bind_port = atoi(optarg);
            break;
        case 'i':
            strcpy(opts.init_config, optarg);
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }
    return run_service(&opts);
}
