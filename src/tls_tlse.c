#include "tls_tlse.h"

#include <mongoose.h> // Normally including the tls.h should handle this.
#include <stdlib.h>
#include <string.h>

#if MG_ENABLE_TLSE

#define THESIS_FATAL            -1
#define THESIS_HANDSHAKE_FAILED -2
#define THESIS_RECV_FAILED      -0xFF
#define THESIS_WANT_READ        -0x42
#define THESIS_CONN_RESET       -0x43

#define FD(c_) ((SOCKET) (size_t) (c_)->fd)

/* Private variables */
static bool g_IsInitialized = false;
static struct TLSContext* g_pServerContext = NULL;

/* Private functions */
static struct mg_str mg_loadfile(struct mg_fs *fs, const char *path);
static int thesis_verify_signature(struct TLSContext* context, struct TLSCertificate **cert, int len);

void mg_tls_init(struct mg_connection *c, const struct mg_tls_opts *opts)
{
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
    if (!g_IsInitialized)
    {
        tls_init();
        g_IsInitialized = true;
    }

    const unsigned char is_server = 1;
    g_pServerContext = tls_create_context(is_server, MG_TLSE_VERSION);

    if (g_pServerContext == NULL)
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
        rc = tls_load_root_certificates(g_pServerContext, (unsigned char*)s.ptr, s.len + 1);

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
        rc = tls_load_certificates(g_pServerContext, (unsigned char*)s.ptr, s.len + 1);
        if (rc == 0)
        {
            mg_error(c, "tls_tlse : invalid tls server certificate");
            goto fail;
        }

        // Load the priv key.
        s = mg_loadfile(fs, key);
        rc = tls_load_private_key(g_pServerContext, (unsigned char*)s.ptr, s.len + 1);
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

int send_pending(struct TLSContext* context, void* client_sock)
{
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;

    while ((out_buffer) && (out_buffer_len > 0))
    {
        int res = send((size_t)client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
        if (res <= 0)
        {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }

    MG_DEBUG(("send_pending(%d, %u) -> %d", (size_t)client_sock, out_buffer_len, send_res)); 

    tls_buffer_clear(context);
    return send_res;
}

int do_handshake(struct mg_connection* c,  struct TLSContext* tls, int* len)
{
    int rc = 1;
    int readBytes = 0;
    void* fd = c->fd;
    *len = 0; // set output len to 0.

    unsigned char hsBuffer[0xFFFF];
    while ((readBytes = recv((size_t)fd, hsBuffer, sizeof(hsBuffer), 0)) > 0)
    {
        if (tls_consume_stream(tls, hsBuffer, readBytes, NULL) > 0)
        {
            break;
        }
    }

    *len = readBytes;
    // Send pending.
    send_pending(tls, fd);

    // check if we received enough of data to continue the handshake
    // return failure otherwise.
    // if (readBytes < 0)
    // {
    //     rc = THESIS_HANDSHAKE_FAILED;
    //     mg_error(c, "tls_handshake: failed recv hs data.");
    // }
    // else
    if (readBytes > 0) // Got some data and good to proceed.
    {
        MG_INFO(("do_handshake : read bytes : %d", readBytes));
        while ((readBytes = recv((size_t)fd, hsBuffer, sizeof(hsBuffer), 0)) > 0)
        {
            if (tls_consume_stream(tls, hsBuffer, readBytes, NULL) < 0)
            {
                rc = THESIS_FATAL; // error
                break;
            }
        }

        *len += readBytes;
        send_pending(tls, fd);
    }

    return rc;
}

void mg_tls_handshake(struct mg_connection* c) {
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    int rc = 1;
    int readBytes = 0;

    struct TLSContext* client = tls_accept(g_pServerContext);
    tls->client_context = client;

    // Do handshake until the connection is established,
    // tls_recv and tls_send is not capable of recv/send
    // for the handshake. State machine could be used to implement it,
    // but that depends if the tls_handshake is called by event handler
    // until is_tls_hs is set to 0.
    while (!tls_established(client))
    {
        if (do_handshake(c, client, &readBytes) < 0)
            break;
    }

    if (tls_established(client) == 1)
    {
        MG_DEBUG(("%lu success, data read : %d", c->id, readBytes));
        c->is_tls_hs = 0; // handshake done
    }
    else
    {
        // error
        mg_error(c, "tlse : tls hs failed, ret %d", rc);
    }
}

bool mg_sock_would_block(void);
bool mg_sock_conn_reset(void);

long mg_tls_recv(struct mg_connection* c, void* buf, size_t len)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    int rc = 0;
    size_t bytes_read = 0;

    // Read N bytes into BUF from socket FD.
    // Returns the number read or -1 for errors.
    // extern ssize_t recv (int __fd, void *__buf, size_t __n, int __flags);
    // rc = recv((size_t)c->fd, buf, (int)len, 0);


    // TODO
    // we need to call tls_recv if there's more to read

    // do we check first if tls_read has data to process before recv more?


    // bytes_read = recv ((intptr_t)c->fd, buf, len, 0);
    bytes_read = tls_read(tls->client_context, buf, len);

    if (bytes_read == len)
    {
        MG_DEBUG(("tls_recv(): bytes_read == len\n"));
    }

    // might not be correct either,
    // cleans up the connection just fine but when moving backwards
    // in the clent mongoose tries to do the handshake again.
    // if that's the proper behavior, import the context from saved one.
    if (bytes_read == 0)
    {
        return -1;
    }

    // if (bytes_read == THESIS_FATAL)
    // {
    //     // fatal error
    // }
    // else if (bytes_read == 0)
    // {
    //     // rc = bytes_read; // OK
    // }
    // else
    // {
    //     rc = THESIS_WANT_READ; // MORE DATA
    // }

    // mongoose should handle any pending data
    if (send_pending(tls->client_context, c->fd) > 0)   // send any pending data
    {
        MG_DEBUG(("tls_recv: sent pending data..\n"));
    }

    MG_DEBUG(("tls_recv : bytes recv %u\n", bytes_read));
    rc = bytes_read;

    return rc;
}

long mg_tls_send(struct mg_connection *c, const void *buf, size_t len)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    int rc = 0;

    // Send N bytes of BUF to socket FD.  Returns the number sent or -1.
    // This function is a cancellation point and therefore not marked with __THROW. 
    // extern ssize_t send (int __fd, const void *__buf, size_t __n, int __flags);
    // rc = send((size_t)c->fd, buf, (int)len, 0);

    // assert len > 0
    rc = tls_write(tls->client_context, buf, len); // TODO : Make sure that len is correct.

    // tls_close_notify(tls->pClientContext);

    if (rc < 0)
    {
        int err = errno; // copy over err
        if (err == EWOULDBLOCK || err == EINPROGRESS)
        {
        }
        mg_error(c, "tlse : write failed");
    }
    else
    {
        tls_close_notify(tls->client_context);
        send_pending(tls->client_context, c->fd);
    }
    return rc;
}

size_t mg_tls_pending(struct mg_connection *c)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;
    // pending true is returned if application_buffer_len is > 0
    // tlse does not implement other way to access size of application buffer length
    size_t ret = tls == NULL ? 0 : (size_t) SSL_pending(tls->client_context);
    // MG_DEBUG(("mg_tls_pending(%lu) -> %d", c->id, ret));
    return ret;
}

void mg_tls_free(struct mg_connection* c)
{
    struct mg_tls* tls = (struct mg_tls*)c->tls;

    // Clean up the tls->context.
    SSL_CTX_free(tls->client_context);
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


int thesis_verify_signature(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len)
{
    return 0;
}

#endif
