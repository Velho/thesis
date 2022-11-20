#include "fs.h"
#include "tls.h"
#include "tls_tlse.h"

#if MG_ENABLE_TLSE

#pragma message "THESIS TLS"

// Define the TLS version to 1.3, TODO : Make this compiler opt.
#define MG_TLSE_VERSION DTLS_V13

static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path);


void mg_tls_init(struct mg_connection *c, const struct mg_tls_opts *opts) 
{
    // 1. Allocate the mg_tls context.
    // Setup a mg_fs to load the certificate and priv key from file.
    struct mg_fs *fs = opts->fs == NULL ? &mg_fs_posix : opts->fs;
    struct mg_tls *tls = (struct mg_tls *) calloc(1, sizeof(*tls));
    c->tls = tls;

    if (c->tls == NULL)
    {
        mg_error(c, "TLS_OOM");
        goto fail;
    }

    if (c->is_client)
    {
        mg_error(c, "tlse : is_client");
        goto fail;
    }

    // 2. Initialize the tlse context.

    unsigned char is_server = 1;
    if ((tls->ctx = tls_create_context(is_server, MG_TLSE_VERSION)) == NULL)
    {
        mg_error(c, "tls_create_context");
        goto fail;
    }

    // 2.1. Set any TLS interface options here.

    // 3. Setup the certificates.
    // Add the certificate to the chain.
    //

    int rc = 0;
    struct mg_str s = mg_loadfile(fs, opts->ca);
    rc = tls_load_certificates(tls->ctx, s.ptr, s.len + 1);

    if (opts->ca != '-')
    {
        free(s.ptr);
    }

    if (opts->ca != NULL && opts->ca[0] != '\0')
    {
    }

    /*
    if (!SSL_CTX_check_private_key(server_ctx)) {
        fprintf(stderr, "Private key not loaded\n");
        return -2;
    }
    */
    // 4. Set the mg_connection statuses.


fail:
    c->is_closing = 1;
    free(tls);
}

void mg_tls_handshake(struct mg_connection *c) {
  (void) c;
}
void mg_tls_free(struct mg_connection *c) {
  (void) c;
}
long mg_tls_recv(struct mg_connection *c, void *buf, size_t len) {
  return c == NULL || buf == NULL || len == 0 ? 0 : -1;
}
long mg_tls_send(struct mg_connection *c, const void *buf, size_t len) {
  return c == NULL || buf == NULL || len == 0 ? 0 : -1;
}
size_t mg_tls_pending(struct mg_connection *c) {
  (void) c;
  return 0;
}

static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path) {
    size_t n = 0;
    if (path[0] == '-')
    {
        return mg_str(path);
    }
    char *p = mg_file_read(fs, path, &n);
    return mg_str_n(p, n);
}

#endif
