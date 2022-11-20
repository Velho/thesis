# Thesis

## Mongoose

Just by accepting the mongoose interface and initializing the tlse application correctly.

Mongoose TLS interface implements the following functions
| | | | | |
|--|--|--|--|--|
| mg_tls_init | struct mg_connection * c |  const struct mg_tls_opts * opts | - |
| mg_tls_free | struct mg_connection * c | - | -
| mg_tls_send | struct mg_connection * c | const void * buf | size_t len |
| mg_tls_recv | struct mg_connection * c|  void * buf | size_t len|
| mg_tls_handshake | struct mg_connection * c | - | -
| mg_tls_pending  | struct mg_connection * c | - | -

TLSE can be adapted directly into the mongoose webserver with a custom implementation for the tls_tlse module.

## TODO

* Implement the Certificate chain.
* Finish up the mongoose tls interface.
  * Handshake
  * etc ..
