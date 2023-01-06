#include "tls_tlse.h"

#include <mongoose.h> // Normally including the tls.h should handle this.
#include <stdlib.h>
#include <string.h>

#if MG_ENABLE_TLSE


static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path);
static int mg_tls_err(struct mg_tls *tls, int res);


void mg_tls_init(struct mg_connection *c, const struct mg_tls_opts *opts)
{
    static bool is_initialized = false;

    // 1. Allocate the mg_tls context.
    // Setup a mg_fs to load the certificate and priv key from file.
    struct mg_fs* fs = opts->fs == NULL ? &mg_fs_posix : opts->fs;
    struct mg_tls* tls = (struct mg_tls *) calloc(1, sizeof(*tls));

    c->tls = tls;
    if (c->tls == NULL)
    {
        mg_error(c, "tls_tlse : tls alloc failed.");
        goto fail;
    }

    if (c->is_client)
    {
        mg_error(c, "tls_tlse : is_client is set, server only supported.");
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
        mg_error(c, "tls_tlse : failed to create tls context");
        goto fail;
    }

    // 2.1. Set any TLS interface options here.
    // ..
    // 3. Setup the certificate authority.

    int rc = 0;
    struct mg_str s = { 0 };

    if (opts->ca != NULL && opts->ca[0] != '\0')
    {
        s = mg_loadfile(fs, opts->ca);
        rc = tls_load_root_certificates(tls->ctx, (unsigned char*)s.ptr, s.len + 1);

        if (!rc) // Provided count of root certificates should be > 0.
        {
            mg_error(c, "tls_tlse : failed to load the certificate authorities");
            goto fail;
        }
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
            mg_error(c, "tls_tlse : invalid tls server certificate");
            goto fail;
        }

        // Load the priv key.
        s = mg_loadfile(fs, key);
        rc = tls_load_private_key(tls->ctx, (unsigned char*)s.ptr, s.len + 1);
        // rc should be 1 in case of successfully loaded private key.
        if (rc <= 0)
        {
            mg_error(c, "tls_tlse : invalid tls pk, ret : %d", rc);
            goto fail;
        }
    }

    // 3.3. Ciphers
    // 3.4. Hostname
    // Hostname or servername is set only for the clients connecting to a server.
    // 4. Set the mg_connection statuses.
    c->is_tls = 1;
    c->is_tls_hs = 1;

    MG_DEBUG(("%lu SSL OK", c->id));

    return;
fail:
    c->is_closing = 1;
    mg_tls_free(c);
}

// FIXME : Replace the compatible layer with tlse appropriate functionality ??

void mg_tls_handshake(struct mg_connection* c) {
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    int rc;

    // Set file descriptor with the ssl data.
    SSL_set_fd(tls->ctx, (int) (size_t) c->fd);
    // accept is for the server-side only.
    // mbedtls and openssl accept/ssl_handshake returns error code
    // if still pending READ or WRITE, how this should be handled
    // here? If it's still pending, do we return 0?
    rc = SSL_accept(tls->ctx);
    if (rc)
    {
        MG_DEBUG(("%lu success", c->id));
        c->is_tls_hs = 0; // handshake done
    }
    else
    {
        // error
        mg_error(c, "tlse : tls hs failed, ret %d", rc);
    }
}

long mg_tls_recv(struct mg_connection* c, void* buf, size_t len)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    int n = SSL_read(tls->ctx, buf, (int)len);
    return n == 0 ? -1 : n < 0 && mg_tls_err(tls, n) == 0 ? 0 : n;
}

long mg_tls_send(struct mg_connection *c, const void *buf, size_t len)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    int n = SSL_write(tls->ctx, buf, (int) len);
    return n == 0 ? -1 : n < 0 && mg_tls_err(tls, n) == 0 ? 0 : n;
}
size_t mg_tls_pending(struct mg_connection *c)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    return tls == NULL ? 0 : (size_t) SSL_pending(tls->ctx);
}

void mg_tls_free(struct mg_connection* c)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;

    // Clean up the tls->context.
    SSL_CTX_free(tls->ctx);
    free(tls);

    c->tls = NULL;
}

// static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path);
struct mg_str mg_loadfile(struct mg_fs *fs, const char *path)
{
    size_t n = 0;
    if (path[0] == '-')
    {
        return mg_str(path);
    }
    char *p = mg_file_read(fs, path, &n);
    return mg_str_n(p, n);
}

static int mg_tls_err(struct mg_tls *tls, int res)
{
    int err = SSL_get_error(tls->ctx, res);
    // We've just fetched the last error from the queue.
    // Now we need to clear the error queue. If we do not, then the following
    // can happen (actually reported):
    //  - A new connection is accept()-ed with cert error (e.g. self-signed cert)
    //  - Since all accept()-ed connections share listener's context,
    //  - *ALL* SSL accepted connection report read error on the next poll cycle.
    //    Thus a single errored connection can close all the rest, unrelated ones.
    // Clearing the error keeps the shared SSL_CTX in an OK state.

    return err;
}

#endif

