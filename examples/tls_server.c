#include <mongoose.h>

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
    // TODO : Set up the TLS context.

    struct mg_http_serve_opts opts =
    {
        .root_dir = "." // Serve local dir
    };

    if (ev == MG_EV_ACCEPT)
    {
        struct mg_tls_opts tls_opts =
        {
                .cert = "certs/cert-2048.pem",
                .certkey = "certs/pk-rsa-2048.pem"
        };
        mg_tls_init(c, &tls_opts);
    }
    else if (ev == MG_EV_READ)
    {
        struct mg_iobuf* r = &c->recv;
        MG_INFO(("SERVER got data: %.*s", r->len, r->buf));
        mg_send(c, r->buf, r->len);
    }
    else if (ev == MG_EV_CLOSE)
    {
        MG_INFO(("SERVER disconnected"));
    }
    else if (ev == MG_EV_ERROR)
    {
        MG_INFO(("SERVER error: %s", (char*)ev_data));
    }
    else if (ev == MG_EV_HTTP_MSG)
    {
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Hello, %s\n", "world");
       //  mg_http_serve_dir(c, ev_data, &opts);
    }
    else if (ev == MG_EV_POLL)
    {
    }
    else
    {
        MG_INFO(("SERVER else : %d", ev));
    }
}

int main(int argc, char *argv[]) {
    struct mg_mgr mgr;

    mg_log("Initialized.");
    mg_mgr_init(&mgr);                                        // Init manager

    mg_log("Listening to http://localhost:8000.");
    mg_http_listen(&mgr, "http://localhost:8000", fn, &mgr);  // Setup listener

    for (;;) mg_mgr_poll(&mgr, 1000);                         // Event loop

    mg_mgr_free(&mgr);                                        // Cleanup

    return 0;
}

