/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>

#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "in_stdin.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int process_pack(msgpack_packer *mp_pck,
                               struct flb_in_stdin_config *ctx,
                               char *data, size_t data_size)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object entry;

    /* Queue the data with time field */
    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, data, data_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        entry = result.data;

        if (entry.type == MSGPACK_OBJECT_MAP) {
            msgpack_pack_array(mp_pck, 2);
            flb_pack_time_now(mp_pck);
            msgpack_pack_object(mp_pck, entry);
        }
        else if (entry.type == MSGPACK_OBJECT_ARRAY) {
            msgpack_pack_object(mp_pck, entry);
        }
        else {
            /*
             * Upon exception, acknowledge the user about the problem but continue
             * working, do not discard valid JSON entries.
             */
            flb_plg_error(ctx->ins, "invalid record found, "
                          "it's not a JSON map or array");
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);
    return 0;
}

static inline int pack_regex(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                             struct flb_in_stdin_config *ctx,
                             struct flb_time *t, char *data, size_t data_size)
{
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(t, mp_pck, 0);
    msgpack_sbuffer_write(mp_sbuf, data, data_size);

    return 0;
}

static int in_stdin_collect(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    int bytes = 0;
    int pack_size;
    int ret;
    char *pack;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_in_stdin_config *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    bytes = read(ctx->fd,
                 ctx->buf + ctx->buf_len,
                 sizeof(ctx->buf) - ctx->buf_len - 1);
    flb_plg_trace(ctx->ins, "stdin read() = %i", bytes);

    if (bytes == 0) {
        flb_plg_warn(ctx->ins, "end of file (stdin closed by remote end)");
    }

    if (bytes <= 0) {
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
        flb_engine_exit(config);
        return -1;
    }
    ctx->buf_len += bytes;
    ctx->buf[ctx->buf_len] = '\0';

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    while (ctx->buf_len > 0) {
        /* Try built-in JSON parser */
        if (!ctx->parser) {
            ret = flb_pack_json_state(ctx->buf, ctx->buf_len,
                                      &pack, &pack_size, &ctx->pack_state);
            if (ret == FLB_ERR_JSON_PART) {
                flb_plg_debug(ctx->ins, "data incomplete, waiting for more...");
                msgpack_sbuffer_destroy(&mp_sbuf);
                return 0;
            }
            else if (ret == FLB_ERR_JSON_INVAL) {
                flb_plg_debug(ctx->ins, "invalid JSON message, skipping");
                flb_pack_state_reset(&ctx->pack_state);
                flb_pack_state_init(&ctx->pack_state);
                ctx->pack_state.multiple = FLB_TRUE;
                ctx->buf_len = 0;
                msgpack_sbuffer_destroy(&mp_sbuf);
                return -1;
            }

            /* Process valid packaged records */
            process_pack(&mp_pck, ctx, pack, pack_size);

            /* Move out processed bytes */
            consume_bytes(ctx->buf, ctx->pack_state.last_byte, ctx->buf_len);
            ctx->buf_len -= ctx->pack_state.last_byte;
            ctx->buf[ctx->buf_len] = '\0';

            flb_pack_state_reset(&ctx->pack_state);
            flb_pack_state_init(&ctx->pack_state);
            ctx->pack_state.multiple = FLB_TRUE;

            flb_free(pack);

            flb_input_chunk_append_raw(ins, NULL, 0,
                                       mp_sbuf.data, mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);
            return 0;
        }
        else {
            /* Reset time for each line */
            flb_time_zero(&out_time);

            /* Use the defined parser */
            ret = flb_parser_do(ctx->parser, ctx->buf, ctx->buf_len,
                                &out_buf, &out_size, &out_time);
            if (ret >= 0) {
                if (flb_time_to_double(&out_time) == 0) {
                    flb_time_get(&out_time);
                }
                pack_regex(&mp_sbuf, &mp_pck,
                           ctx, &out_time, out_buf, out_size);
                flb_free(out_buf);
                flb_input_chunk_append_raw(ins, NULL, 0,
                                           mp_sbuf.data, mp_sbuf.size);
                msgpack_sbuffer_clear(&mp_sbuf);
            }
            else {
                /* we need more data ? */
                flb_plg_trace(ctx->ins, "data mismatch or incomplete");
                msgpack_sbuffer_destroy(&mp_sbuf);
                return 0;
            }
        }

        if (ret == ctx->buf_len) {
            ctx->buf_len = 0;
            break;
        }
        else if (ret >= 0) {
            /*
             * 'ret' is the last byte consumed by the regex engine, we need
             * to advance it position.
             */
            ret++;
            consume_bytes(ctx->buf, ret, ctx->buf_len);
            ctx->buf_len -= ret;
            ctx->buf[ctx->buf_len] = '\0';
        }
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    return 0;
}

/* Initialize plugin */
static int in_stdin_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int fd;
    int ret;
    const char *tmp;
    struct flb_in_stdin_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_stdin_config));
    if (!ctx) {
        return -1;
    }
    ctx->buf_len = 0;
    ctx->ins = in;

    /* Clone the standard input file descriptor */
    fd = dup(STDIN_FILENO);
    if (fd == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "Could not open standard input!");
        flb_free(ctx);
        return -1;
    }
    ctx->fd = fd;

    tmp = flb_input_get_property("parser", in);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_plg_error(ctx->ins, "requested parser '%s' not found", tmp);
        }
    }
    else {
        ctx->parser = NULL;
    }

    /* Always initialize built-in JSON pack state */
    flb_pack_state_init(&ctx->pack_state);
    ctx->pack_state.multiple = FLB_TRUE;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_stdin_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for STDIN input plugin");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

/* Cleanup serial input */
static int in_stdin_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_stdin_config *ctx = in_context;

    if (!ctx) {
        return 0;
    }

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }
    flb_pack_state_reset(&ctx->pack_state);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_stdin_plugin = {
    .name         = "stdin",
    .description  = "Standard Input",
    .cb_init      = in_stdin_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_stdin_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_stdin_exit
};
