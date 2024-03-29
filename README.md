# Thesis

## Build

### Repository

Git clone the project,
`git clone https://../.git`

Initialize the submodules (submodules found under 'deps' folder).
`git submodule update --init`

### CMake Configuration

| Name | Description | Default value |
|-|-|-|
| THESIS_BUILD_EXAMPLES |Build sample application| OFF |
| THESIS_TLSE_UNIT_TESTS | Build unit tests | ON |
| THESIS_BUILD_MONGOOSE  | Build [mongoose](#mongoose) | OFF |
| __DEPRECATED__ ~~THESIS_BUILD_AS_LIBRARY~~  | ~~Link against [mongoose](#mongoose)~~ | OFF |
| THESIS_COMPILE_DEFINITONS | | |

### Compiling

Compiler version used to test, (minimum requirements):
  * GCC     12.2.0
  * Clang   14.0.6
  * CMake   3.25.1

3rd-party dependencies:
  - None
Posix library compatible, requires the posix threads library
for the unit tests (libcheck).

Building the library :

1) Create folder for the build
`mkdir .build`
2) Run the CMake configuration
`cmake -S . -B .build`
or
`cmake -G "Generator" -S . -B .build`

3) Building the project either from the root folder or the build folder
`cmake --build .build`
or
```
cd .build/
make
```
4) Unit tests
```
cd .build/
make test
```

## Mongoose

Mongoose can be built as part of this project or from outside as this library
implements the tls interface for the mongoose so only the headers are required
for the library compilation. The option to build as library is not anymore used.
If build mongoose is not set, configuration still assumes the mongoose target
can be found.

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
* Add unit tests, which tests the implemented interface.

## TLS

### Handshake

* The handshake begins when a client connects to a TLS-enabled server requesting a secure connection and the client presents a list of supported cipher suites (ciphers and hash functions).
* From this list, the server picks a cipher and hash function that it also supports and notifies the client of the decision.
* The server usually then provides identification in the form of a digital certificate. The certificate contains the server name, the trusted certificate authority (CA) that vouches for the authenticity of the certificate, and the server's public encryption key.
* The client confirms the validity of the certificate before proceeding.
* To generate the session keys used for the secure connection, the client either:
    * encrypts a random number (PreMasterSecret) with the server's public key and sends the result to the server (which only the server should be able to decrypt with its private key); both parties then use the random number to generate a unique session key for subsequent encryption and decryption of data during the session, or
    * uses Diffie–Hellman key exchange (or its variant elliptic-curve DH) to securely generate a random and unique session key for encryption and decryption that has the additional property of forward secrecy: if the server's private key is disclosed in future, it cannot be used to decrypt the current session, even if the session is intercepted and recorded by a third party.

This concludes the handshake and begins the secured connection, which is encrypted and decrypted with the session key until the connection closes. If any one of the above steps fails, then the TLS handshake fails and the connection is not created.


### Properties

* The connection is private (or secure) because a symmetric-key algorithm is used to encrypt the data transmitted. The keys for this symmetric encryption are generated uniquely for each connection and are based on a shared secret that was negotiated at the start of the session. The server and client negotiate the details of which encryption algorithm and cryptographic keys to use before the first byte of data is transmitted (see below). The negotiation of a shared secret is both secure (the negotiated secret is unavailable to eavesdroppers and cannot be obtained, even by an attacker who places themself in the middle of the connection) and reliable (no attacker can modify the communications during the negotiation without being detected).
* The identity of the communicating parties can be authenticated using public-key cryptography. This authentication is required for the server and optional for the client.
* he connection is reliable because each message transmitted includes a message integrity check using a message authentication code to prevent undetected loss or alteration of the data during transmission.

