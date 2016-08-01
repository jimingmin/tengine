#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <GraphicsMagick/wand/magick_wand.h>

#include "wand/magick_wand.h"

#define NGX_HTTP_GRAPHICS_OFF       0
#define NGX_HTTP_GRAPHICS_TEST      1
#define NGX_HTTP_GRAPHICS_SIZE      2
#define NGX_HTTP_GRAPHICS_RESIZE    3
#define NGX_HTTP_GRAPHICS_CROP      4
#define NGX_HTTP_GRAPHICS_ROTATE    5
#define NGX_HTTP_GRAPHICS_CROP_KEEPX       6
#define NGX_HTTP_GRAPHICS_CROP_KEEPY       7

#define NGX_HTTP_GRAPHICS_START     0
#define NGX_HTTP_GRAPHICS_READ      1
#define NGX_HTTP_GRAPHICS_PROCESS   2
#define NGX_HTTP_GRAPHICS_PASS      3
#define NGX_HTTP_GRAPHICS_DONE      4

#define NGX_HTTP_GRAPHICS_NONE      0
#define NGX_HTTP_GRAPHICS_JPEG      1
#define NGX_HTTP_GRAPHICS_GIF       2
#define NGX_HTTP_GRAPHICS_PNG       3
#define NGX_HTTP_GRAPHICS_WEBP      4

#define NGX_HTTP_GRAPHICS_OFFSET_CENTER    0
#define NGX_HTTP_GRAPHICS_OFFSET_LEFT      1
#define NGX_HTTP_GRAPHICS_OFFSET_RIGHT     2
#define NGX_HTTP_GRAPHICS_OFFSET_TOP       3
#define NGX_HTTP_GRAPHICS_OFFSET_BOTTOM    4

#define NGX_HTTP_GRAPHICS_BUFFERED  0x08

typedef struct {
    ngx_uint_t                   filter;
    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   angle;
    ngx_uint_t                   jpeg_quality;
    ngx_uint_t                   sharpen;
    ngx_uint_t                   offset_x;
    ngx_uint_t                   offset_y;

    ngx_flag_t                   transparency;
    ngx_flag_t                   interlace;

    ngx_http_complex_value_t    *wcv;
    ngx_http_complex_value_t    *hcv;
    ngx_http_complex_value_t    *oxcv;
    ngx_http_complex_value_t    *oycv;
    ngx_http_complex_value_t    *acv;
    ngx_http_complex_value_t    *jqcv;
    ngx_http_complex_value_t    *shcv;

    size_t                       buffer_size;
} ngx_http_graphics_filter_conf_t;

typedef struct {
    u_char                      *image;
    u_char                      *last;

    size_t                       length;
    size_t                       image_size;

    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   max_width;
    ngx_uint_t                   max_height;
    ngx_uint_t                   offset_x;
    ngx_uint_t                   offset_y;
    ngx_uint_t                   angle;

    ngx_uint_t                   phase;
    ngx_uint_t                   type;
    ngx_uint_t                   force;
} ngx_http_graphics_filter_ctx_t;

static ngx_int_t ngx_http_graphics_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_graphics_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_graphics_json(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx);
static void ngx_http_graphics_length(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_uint_t ngx_http_graphics_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_graphics_send(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_graphics_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_graphics_process(ngx_http_request_t *r);
static ngx_int_t ngx_http_graphics_size(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx);
static ngx_uint_t ngx_http_graphics_filter_get_value(ngx_http_request_t *r, ngx_http_complex_value_t *cv, ngx_uint_t v);
static ngx_uint_t ngx_http_graphics_filter_value(ngx_str_t *value);
static ngx_buf_t *ngx_http_graphics_asis(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx);
static ngx_int_t ngx_http_graphics_want_origin_file_format(ngx_str_t *uri);
static void *ngx_http_graphics_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_graphics_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_graphics_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_buf_t *ngx_http_graphics_resize(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx);
static MagickWand *ngx_http_graphics_source(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx);
static void ngx_http_graphics_cleanup(void *data);
static char *ngx_http_graphics_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_graphics_filter_init(ngx_conf_t *cf);

static ngx_command_t    ngx_http_graphics_filter_commands[] = {
      { ngx_string("graphics_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_graphics_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
      { ngx_string("graphics_filter_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_graphics_filter_conf_t, buffer_size),
      NULL },
      
      { ngx_string("graphics_filter_jpeg_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_graphics_filter_jpeg_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
      ngx_null_command
};

static ngx_http_module_t  ngx_http_graphics_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_graphics_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_graphics_filter_create_conf,     /* create location configuration */
    ngx_http_graphics_filter_merge_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_graphics_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_graphics_filter_module_ctx,     /* module context */
    ngx_http_graphics_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_str_t  ngx_http_graphics_types[] = {
    ngx_string("image/jpeg"),
    ngx_string("image/gif"),
    ngx_string("image/png"),
    ngx_string("image/webp")
};

static ngx_int_t
ngx_http_graphics_header_filter(ngx_http_request_t *r)
{
    off_t                          len;
    ngx_http_graphics_filter_ctx_t   *ctx;
    ngx_http_graphics_filter_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_graphics_filter_module);

    if (ctx) {
        ngx_http_set_ctx(r, NULL, ngx_http_graphics_filter_module);
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_graphics_filter_module);

    if (conf->filter == NGX_HTTP_GRAPHICS_OFF) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "graphics filter: multipart/x-mixed-replace response");

        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_graphics_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_graphics_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "graphics filter: too big response: %O", len);

        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_graphics_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_str_t                     *ct;
    ngx_chain_t                    out;
    ngx_http_graphics_filter_ctx_t   *ctx;
    ngx_http_graphics_filter_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "graphics filter");

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_graphics_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NGX_HTTP_GRAPHICS_START:

        ctx->type = ngx_http_graphics_test(r, in);

        conf = ngx_http_get_module_loc_conf(r, ngx_http_graphics_filter_module);

        if (ctx->type == NGX_HTTP_GRAPHICS_NONE) {

            if (conf->filter == NGX_HTTP_GRAPHICS_SIZE) {
                out.buf = ngx_http_graphics_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = NGX_HTTP_GRAPHICS_DONE;

                    return ngx_http_graphics_send(r, ctx, &out);
                }
            }

            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_graphics_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        ct = &ngx_http_graphics_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == NGX_HTTP_GRAPHICS_TEST) {
            ctx->phase = NGX_HTTP_GRAPHICS_PASS;

            return ngx_http_graphics_send(r, ctx, in);
        }

        ctx->phase = NGX_HTTP_GRAPHICS_READ;

        /* fall through */

    case NGX_HTTP_GRAPHICS_READ:

        rc = ngx_http_graphics_read(r, in);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }
        
//        ctx->length = ctx->image_size;

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_graphics_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NGX_HTTP_GRAPHICS_PROCESS:

        out.buf = ngx_http_graphics_process(r);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_graphics_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_GRAPHICS_PASS;

        return ngx_http_graphics_send(r, ctx, &out);

    case NGX_HTTP_GRAPHICS_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_GRAPHICS_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}

static ngx_uint_t
ngx_http_graphics_test(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NGX_HTTP_GRAPHICS_NONE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return NGX_HTTP_GRAPHICS_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return NGX_HTTP_GRAPHICS_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return NGX_HTTP_GRAPHICS_PNG;
    } else if(p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
              && p[4] == 0x30 && p[5] == 0x5b && p[6] == 0x00 && p[7] == 0x00
              && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
    {
        /* WEBP */
        
        return NGX_HTTP_GRAPHICS_WEBP;
    }

    return NGX_HTTP_GRAPHICS_NONE;
}

static ngx_buf_t *
ngx_http_graphics_json(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx)
{
    size_t      len;
    ngx_buf_t  *b;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    ngx_http_clean_header(r);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        ngx_http_graphics_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * NGX_SIZE_T_LEN;

    b->pos = ngx_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = ngx_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          ngx_http_graphics_types[ctx->type - 1].data + 6);

    ngx_http_graphics_length(r, b);

    return b;
}

static void
ngx_http_graphics_length(ngx_http_request_t *r, ngx_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}

static ngx_int_t
ngx_http_graphics_send(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_GRAPHICS_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}

static ngx_int_t
ngx_http_graphics_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_graphics_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_graphics_filter_module);

    if (ctx->image == NULL) {
        ctx->image = ngx_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NGX_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "graphics buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "graphics filter: too big response");
            return NGX_ERROR;
        }

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        ctx->image_size += size;
        
        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NGX_HTTP_GRAPHICS_BUFFERED;

    return NGX_AGAIN;
}

static ngx_buf_t *
ngx_http_graphics_process(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_graphics_filter_ctx_t   *ctx;
    ngx_http_graphics_filter_conf_t  *conf;

    r->connection->buffered &= ~NGX_HTTP_GRAPHICS_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_graphics_filter_module);

    rc = ngx_http_graphics_size(r, ctx);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_graphics_filter_module);

    if (conf->filter == NGX_HTTP_GRAPHICS_SIZE) {
        return ngx_http_graphics_json(r, rc == NGX_OK ? ctx : NULL);
    }

    ctx->angle = ngx_http_graphics_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == NGX_HTTP_GRAPHICS_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return ngx_http_graphics_resize(r, ctx);
    }

    ctx->max_width = ngx_http_graphics_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = ngx_http_graphics_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == NGX_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force)
    {
        return ngx_http_graphics_asis(r, ctx);
    }

    return ngx_http_graphics_resize(r, ctx);
}

static ngx_int_t
ngx_http_graphics_size(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    ngx_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case NGX_HTTP_GRAPHICS_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return NGX_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case NGX_HTTP_GRAPHICS_GIF:

        if (ctx->length < 10) {
            return NGX_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case NGX_HTTP_GRAPHICS_PNG:

        if (ctx->length < 24) {
            return NGX_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case NGX_HTTP_GRAPHICS_WEBP:
        if(ctx->length < 30) {
            return NGX_DECLINED;
        }
        
        width = p[26] * 256 + p[27];
        height = p[28] * 256 + p[29];
        
        break;
    default:

        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics size: %d x %d", width, height);

    ctx->width = width;
    ctx->height = height;

    return NGX_OK;
}

static ngx_uint_t
ngx_http_graphics_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v)
{
    ngx_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
        return 0;
    }

    return ngx_http_graphics_filter_value(&val);
}

static ngx_uint_t
ngx_http_graphics_filter_value(ngx_str_t *value)
{
    ngx_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (ngx_uint_t) -1;
    }

    n = ngx_atoi(value->data, value->len);

    if (n == NGX_ERROR) {
        if (value->len == sizeof("left") - 1
            && ngx_strncmp(value->data, "left", value->len) == 0)
        {
            return NGX_HTTP_GRAPHICS_OFFSET_LEFT;
        } else if (value->len == sizeof("right") - 1
                   && ngx_strncmp(value->data, "right", sizeof("right") - 1) == 0)
        {
            return NGX_HTTP_GRAPHICS_OFFSET_RIGHT;
        } else if (value->len == sizeof("top") - 1
                   && ngx_strncmp(value->data, "top", sizeof("top") - 1) == 0)
        {
            return NGX_HTTP_GRAPHICS_OFFSET_TOP;
        } else if (value->len == sizeof("bottom") - 1
                   && ngx_strncmp(value->data, "bottom", sizeof("bottom") - 1) == 0)
        {
            return NGX_HTTP_GRAPHICS_OFFSET_BOTTOM;
        } else {
            return NGX_HTTP_GRAPHICS_OFFSET_CENTER;
        }
    } else if (n > 0) {
        return (ngx_uint_t) n;
    }

    return 0;
}

static ngx_buf_t *
ngx_http_graphics_asis(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx)
{
    ngx_buf_t                     *b;
    MagickWand                    *wand;
    u_char                        *image_start, *image_last;
    size_t                         image_size;
    MagickPassFail                 status;
    ExceptionType                  severity;
    char                          *description;
    ngx_pool_cleanup_t            *cln;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    image_start = ctx->image;
    image_last = ctx->last;
    
    cln = ngx_pool_cleanup_add(r->pool, 0);
    
    if(ctx->type != NGX_HTTP_GRAPHICS_WEBP && !ngx_http_graphics_want_origin_file_format(&r->raw_uri) && cln != NULL) {
        wand = ngx_http_graphics_source(r, ctx);
        
        status = MagickSetImageFormat(wand, "webp");
        if(status != MagickPass) {
            description = MagickGetException(wand, &severity);
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics set image format failed : %s", description);
            
            DestroyMagickWand(wand);
        } else {
            image_start = MagickWriteImageBlob(wand, &image_size);
            image_last = image_start + image_size;
            
            ngx_pfree(r->pool, ctx->image);
            
            cln->handler = ngx_http_graphics_cleanup;
            cln->data = wand;
        }
    }
    
    b->pos = image_start;
    b->last = image_last;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_graphics_length(r, b);

    return b;
}

static ngx_int_t
ngx_http_graphics_want_origin_file_format(ngx_str_t *uri) {
    if(uri == NULL) {
        return 0;
    }
    
    if(ngx_strstr(uri->data, "! HTTP") != NULL) {
        return 1;
    }
    
    return 0;
}

static void *
ngx_http_graphics_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_graphics_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_graphics_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jqcv = NULL;
     *     conf->shcv = NULL;
     */

    conf->filter = NGX_CONF_UNSET_UINT;
    conf->jpeg_quality = NGX_CONF_UNSET_UINT;
    conf->sharpen = NGX_CONF_UNSET_UINT;
    conf->angle = NGX_CONF_UNSET_UINT;
    conf->transparency = NGX_CONF_UNSET;
    conf->interlace = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->offset_x = NGX_CONF_UNSET_UINT;
    conf->offset_y = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_graphics_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_graphics_filter_conf_t *prev = parent;
    ngx_http_graphics_filter_conf_t *conf = child;

    if (conf->filter == NGX_CONF_UNSET_UINT) {

        if (prev->filter == NGX_CONF_UNSET_UINT) {
            conf->filter = NGX_HTTP_GRAPHICS_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    if (conf->jpeg_quality == NGX_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        ngx_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->sharpen == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    if (conf->angle == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->angle, prev->angle, 0);

        if (conf->acv == NULL) {
            conf->acv = prev->acv;
        }
    }

    ngx_conf_merge_value(conf->transparency, prev->transparency, 1);

    ngx_conf_merge_value(conf->interlace, prev->interlace, 0);

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    if (conf->offset_x == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->offset_x, prev->offset_x,
                                  NGX_HTTP_GRAPHICS_OFFSET_CENTER);

        if (conf->oxcv == NULL) {
            conf->oxcv = prev->oxcv;
        }
    }

    if (conf->offset_y == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->offset_y, prev->offset_y,
                                  NGX_HTTP_GRAPHICS_OFFSET_CENTER);

        if (conf->oycv == NULL) {
            conf->oycv = prev->oycv;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_graphics_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_graphics_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_uint_t                         i;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[i].data, "off") == 0) {
            imcf->filter = NGX_HTTP_GRAPHICS_OFF;

        } else if (ngx_strcmp(value[i].data, "test") == 0) {
            imcf->filter = NGX_HTTP_GRAPHICS_TEST;

        } else if (ngx_strcmp(value[i].data, "size") == 0) {
            imcf->filter = NGX_HTTP_GRAPHICS_SIZE;

        } else {
            goto failed;
        }

        return NGX_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (ngx_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != NGX_HTTP_GRAPHICS_RESIZE
                && imcf->filter != NGX_HTTP_GRAPHICS_CROP)
            {
                imcf->filter = NGX_HTTP_GRAPHICS_ROTATE;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = ngx_http_graphics_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (ngx_uint_t) n;

            } else {
                imcf->acv = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return NGX_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return NGX_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (ngx_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = NGX_HTTP_GRAPHICS_RESIZE;

    } else if (ngx_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = NGX_HTTP_GRAPHICS_CROP;

    } else if (ngx_strcmp(value[i].data, "crop_keepx") == 0) {
        imcf->filter = NGX_HTTP_GRAPHICS_CROP_KEEPX;

    } else if (ngx_strcmp(value[i].data, "crop_keepy") == 0) {
        imcf->filter = NGX_HTTP_GRAPHICS_CROP_KEEPY;

    } else {
        goto failed;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_graphics_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (ngx_uint_t) n;

    } else {
        imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_graphics_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (ngx_uint_t) n;

    } else {
        imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return NGX_CONF_OK;

failed:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}

static ngx_buf_t *
ngx_http_graphics_resize(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy;
    u_char                        *out;
    size_t                         out_size;
    ngx_buf_t                     *b;
    ngx_uint_t                     resize;
    MagickWand                    *wand;
    PixelWand                     *background;
    ngx_pool_cleanup_t            *cln;
    ngx_http_graphics_filter_conf_t  *conf;
    MagickPassFail                 status;
    ExceptionType                  severity;
    char                          *description;
    
    wand = ngx_http_graphics_source(r, ctx);

    if (wand == NULL) {
        return NULL;
    }
    
    sx = MagickGetImageWidth(wand);
    sy = MagickGetImageHeight(wand);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_graphics_filter_module);

    if (!ctx->force
        && ctx->angle == 0
        && (ngx_uint_t) sx <= ctx->max_width
        && (ngx_uint_t) sy <= ctx->max_height)
    {
        DestroyMagickWand(wand);
        return ngx_http_graphics_asis(r, ctx);
    }
    
    dx = sx;
    dy = sy;
    
    if (conf->filter == NGX_HTTP_GRAPHICS_RESIZE) {
        if ((ngx_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }
        
        resize = 1;
    } else if(conf->filter == NGX_HTTP_GRAPHICS_ROTATE) {
        
        resize = 0;
        
    }  else { /* NGX_HTTP_GRAPHICS_CROP */
        if (conf->filter == NGX_HTTP_GRAPHICS_CROP_KEEPX) {
            if ((ngx_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else if (conf->filter == NGX_HTTP_GRAPHICS_CROP_KEEPY) {
            if ((ngx_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }

        } else if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((ngx_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((ngx_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }
    
    status = MagickPass;
    
    if(resize) { 
        status = MagickResizeImage(wand, dx, dy, LanczosFilter, 1.0);
    } else {
        background = NewPixelWand();
        PixelSetColor(background,"#000000");
        status = MagickRotateImage(wand, background, ctx->angle);
        DestroyPixelWand(background);
    }
    
    if(status != MagickPass) {
        description = MagickGetException(wand, &severity);
        if(resize) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics resize failed : %s", description);
        } else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics rotate failed : %s", description);
        }
        
        DestroyMagickWand(wand);
        return NULL;
    }
    
    if (conf->filter == NGX_HTTP_GRAPHICS_CROP
        || conf->filter == NGX_HTTP_GRAPHICS_CROP_KEEPX
        || conf->filter == NGX_HTTP_GRAPHICS_CROP_KEEPY) {

        if ((ngx_uint_t) dx > ctx->max_width && ctx->max_width > 0) {
            ox = (dx - ctx->max_width) / 2;
        } else {
            ox = 0;
        }

        if ((ngx_uint_t) dy > ctx->max_height && ctx->max_height > 0) {
            oy = (dy - ctx->max_height) / 2;
        } else {
            oy = 0;
        }
        
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "graphics crop: %d x %d @ %d x %d",
               dx, dy, ox, oy);

        status = MagickCropImage(wand, ctx->max_width, ctx->max_height, ox, oy);
        if(status != MagickPass) {
            description = MagickGetException(wand, &severity);
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "graphics crop failed : %s", description);
            
            DestroyMagickWand(wand);
            return NULL;
        }
    }
    
    status = MagickSetCompressionQuality(wand, conf->jpeg_quality);
    if(status != MagickPass) {
        description = MagickGetException(wand, &severity);
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
           "graphics compression quality failed : %s", description);

        DestroyMagickWand(wand);
        return NULL;
    }
//    sharpen = ngx_http_graphics_filter_get_value(r, conf->shcv, conf->sharpen);
//    if (sharpen > 0) {
//        MagickSharpenImage(wand, sharpen);
//    }

//    MagickSetImageInterlaceScheme(wand, (int) conf->interlace);

    if(ctx->type != NGX_HTTP_GRAPHICS_WEBP && !ngx_http_graphics_want_origin_file_format(&r->raw_uri)) {
        status = MagickSetImageFormat(wand, "webp");
        if(status != MagickPass) {
            description = MagickGetException(wand, &severity);
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics set image format failed : %s", description);

            DestroyMagickWand(wand);
            return NULL;
        }
    }
    
    out = MagickWriteImageBlob(wand, &out_size);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "graphics: %d x %d %d", sx, sy, colors);

    ngx_pfree(r->pool, ctx->image);

    if (out == NULL) {
        DestroyMagickWand(wand);
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        DestroyMagickWand(wand);
        return NULL;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        DestroyMagickWand(wand);
        return NULL;
    }

    cln->handler = ngx_http_graphics_cleanup;
    cln->data = wand;

    b->pos = out;
    b->last = out + out_size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_graphics_length(r, b);

    return b;
}

static MagickWand *
ngx_http_graphics_source(ngx_http_request_t *r, ngx_http_graphics_filter_ctx_t *ctx)
{
    char        *failed;
    MagickWand  *wand;
    ExceptionType severity;

    failed = NULL;
    wand = NULL;

    if(ctx->type == NGX_HTTP_GRAPHICS_JPEG || ctx->type == NGX_HTTP_GRAPHICS_GIF
            || ctx->type == NGX_HTTP_GRAPHICS_PNG || ctx->type == NGX_HTTP_GRAPHICS_WEBP) {
        wand = NewMagickWand();
        
        if(MagickReadImageBlob(wand, ctx->image, ctx->image_size) != 1) {
            failed = MagickGetException(wand, &severity);
            DestroyMagickWand(wand);
            wand = NULL;
        }
    } else {
        failed = "unknown image type";
    }
    
    if(failed != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }
    
    return wand;
}

static void
ngx_http_graphics_cleanup(void *data)
{
    if(data != NULL) {
        DestroyMagickWand((MagickWand *)data);
    }
}

static char *
ngx_http_graphics_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_graphics_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_graphics_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->jpeg_quality = (ngx_uint_t) n;

    } else {
        imcf->jqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_graphics_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_graphics_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_graphics_body_filter;
    
    InitializeMagick(NULL);

    return NGX_OK;
}
