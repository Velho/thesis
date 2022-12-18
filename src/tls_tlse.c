#include "tls_tlse.h"

#include <mongoose.h> // Normally including the tls.h should handle this.
#include <stdlib.h>
#include <string.h>

#if MG_ENABLE_TLSE

// Define the TLS version to 1.3, TODO : Make this compiler opt.
#define MG_TLSE_VERSION TLS_V13

static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path);
// Is this required to be declaration?
// static void mg_tls_free(struct mg_connection *c);

void mg_tls_init(struct mg_connection *c, const struct mg_tls_opts *opts) 
{
    static bool is_initialized = false;

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

    // Before creating the context, calling tls_init() if not initialized.
    // Global init function, not thread-safe.
    if (!is_initialized)
    {
        tls_init();
        is_initialized = true;
    }

    const unsigned char is_server = 1;
    TLS* ctx = tls_create_context(is_server, MG_TLSE_VERSION);
    tls->ctx = ctx;

    if (tls->ctx == NULL)
    {
        mg_error(c, "tls_create_context");
        goto fail;
    }


    // 2.1. Set any TLS interface options here.
    // ..
    // 3. Setup the certificate authority.

    // ca must be specified to load the file.
    if (opts->ca == NULL)
    {
        mg_error(c, "Certificate authority not specified.");
        goto fail;
    }

    int rc = 0;
    struct mg_str s = mg_loadfile(fs, opts->ca);
    rc = tls_load_certificates(tls->ctx, (unsigned char*)s.ptr, s.len + 1);

    if (!rc) // Provided count of certificates should be > 0.
    {
        mg_error(c, "Failed to load the certificates");
        goto fail;
    }

    // 3.1 Setup the pk

    if (opts->cert != NULL && opts->cert[0] != '\0') 
    {
        const char* key = opts->certkey == NULL ? opts->cert : opts->certkey;

        // Load the cert key.
        s = mg_loadfile(fs, opts->cert);
        rc = tls_load_certificates(tls->ctx, (unsigned char*)s.ptr, s.len + 1);
        if (rc == 0)
        {
            mg_error(c, "Invalid tls server cert.");
            goto fail;
        }

        // Load the priv key.
        s = mg_loadfile(fs, key);
        rc = tls_load_private_key(tls->ctx, (unsigned char*)s.ptr, s.len + 1);
        // rc should be 1 in case of successfully loaded private key. 
        if (rc == 0)
        {
            mg_error(c, "Invalid tls pk.");
            goto fail;
        }
    }

    // 4. Set the mg_connection statuses.
    c->is_tls = 1;
    c->is_tls_hs = 1;

    MG_DEBUG(("%lu SSL OK", c->id));

    return; // FIXME : return for now.

fail:
    c->is_closing = 1;
    mg_tls_free(c);
}

void mg_tls_handshake(struct mg_connection *c) {
    struct mg_tls *tls = (struct mg_tls *)c->tls;

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

// static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path);
struct mg_str mg_loadfile(struct mg_fs *fs, const char *path) {
    size_t n = 0;
    if (path[0] == '-')
    {
        return mg_str(path);
    }
    char *p = mg_file_read(fs, path, &n);
    return mg_str_n(p, n);
}

void mg_tls_free(struct mg_connection *c)
{
    struct mg_tls* tls = (struct mg_tls *)c->tls;

    // Clean up the tls->context.

    // free(tls);
    // c->tls = NULL;
}

#endif
