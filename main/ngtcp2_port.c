#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <inttypes.h>
#include <quic_init_client.h>

void app_main(void) {
    // Initialize wolfSSL library
    wolfSSL_Init();

    // Create a wolfSSL context
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("wolfSSL_CTX_new error\n");
        wolfSSL_Cleanup();
        return;
    }
    printf("wolfSSL context created successfully.\n");

    ngtcp2_path path = set_ngtcp2_path("192.168.1.2", "192.168.1.1", 12345, 443);
    quic_client_init(path);

    quic_client_cleanup();
    
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    printf("wolfSSL cleaned up.\n");
}
