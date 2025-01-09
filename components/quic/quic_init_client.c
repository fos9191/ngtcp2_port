#include <ngtcp2/ngtcp2.h>
#include "ngtcp2/ngtcp2_crypto.h"
#include "quic_init_client.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <wolfssl/wolfcrypt/random.h>
#include <time.h>

static ngtcp2_conn *conn;

int RAND_bytes(unsigned char *buffer, int num) {
    // Initialize the random seed only once (if it's not already done)
    static int initialized = 0;
    if (!initialized) {
        srand((unsigned int)time(NULL));  // Seed the random number generator with the current time
        initialized = 1;
    }

    // Generate random bytes
    for (int i = 0; i < num; i++) {
        buffer[i] = (unsigned char)(rand() & 0xFF);  // rand() produces an integer, mask to get a byte
    }
    
    return 1;  // Indicate success
}

int rand_function(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    return rand();
}

int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                             size_t cidlen, void *user_data) {
    // TODO: Generate a new connection ID meaningfully
    return rand();
}

void log_printf(void *user_data, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

ngtcp2_path set_ngtcp2_path(const char *local_ip, const char *remote_ip, uint16_t local_port, uint16_t remote_port) {
    ngtcp2_path path;
    ngtcp2_addr local_addr, remote_addr;

    ngtcp2_addr_init(&local_addr, local_ip, local_port);
    ngtcp2_addr_init(&remote_addr, remote_ip, remote_port);

    path.local = local_addr;
    path.remote = remote_addr;
    return path;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {
#ifdef MESSAGE
  struct client *c = user_data;
  int rv;
  int64_t stream_id;
  (void)max_streams;

  if (c->stream.stream_id != -1) {
    return 0;
  }

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  if (rv != 0) {
    return 0;
  }

  c->stream.stream_id = stream_id;
  c->stream.data = (const uint8_t *)MESSAGE;
  c->stream.datalen = sizeof(MESSAGE) - 1;

  return 0;
#else  /* !defined(MESSAGE) */
  (void)conn;
  (void)max_streams;
  (void)user_data;

  return 0;
#endif /* !defined(MESSAGE) */
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  size_t i;
  (void)rand_ctx;

  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)random();
  }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}


int quic_client_init(ngtcp2_path path) {
    ngtcp2_callbacks callbacks = {
        ngtcp2_crypto_client_initial_cb,
        NULL, /* recv_client_initial */
        ngtcp2_crypto_recv_crypto_data_cb,
        NULL, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        NULL, /* recv_stream_data */
        NULL, /* acked_stream_data_offset */
        NULL, /* stream_open */
        NULL, /* stream_close */
        NULL, /* recv_stateless_reset */
        ngtcp2_crypto_recv_retry_cb,
        extend_max_local_streams_bidi,
        NULL, /* extend_max_local_streams_uni */
        rand_cb,
        get_new_connection_id_cb,
        NULL, /* remove_connection_id */
        ngtcp2_crypto_update_key_cb,
        NULL, /* path_validation */
        NULL, /* select_preferred_address */
        NULL, /* stream_reset */
        NULL, /* extend_max_remote_streams_bidi */
        NULL, /* extend_max_remote_streams_uni */
        NULL, /* extend_max_stream_data */
        NULL, /* dcid_status */
        NULL, /* handshake_confirmed */
        NULL, /* recv_new_token */
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        NULL, /* recv_datagram */
        NULL, /* ack_datagram */
        NULL, /* lost_datagram */
        ngtcp2_crypto_get_path_challenge_data_cb,
        NULL, /* stream_stop_sending */
        ngtcp2_crypto_version_negotiation_cb,
        NULL, /* recv_rx_key */
        NULL, /* recv_tx_key */
        NULL, /* early_data_rejected */
    };
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params transport_params;
    int rv;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    scid.datalen = 8;
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    printf("dcid is: ");
    for (size_t i = 0; i < dcid.datalen; i++) {
        printf("%02x", dcid.data[i]);  // Print each byte as a 2-digit hexadecimal value
    }
    printf("\n");

    printf("scid is: ");
    for (size_t i = 0; i < scid.datalen; i++) {
        printf("%02x", scid.data[i]);  // Print each byte as a 2-digit hexadecimal value
    }
    printf("\n");

    // Initialize settings
    ngtcp2_settings_default(&settings);
    settings.log_printf = log_printf;

    // Initialize transport parameters
    /*
    memset(&transport_params, 0, sizeof(transport_params));
    transport_params.initial_max_stream_data_bidi_local = 65536;
    transport_params.initial_max_data = 1048576;
    transport_params.initial_max_streams_bidi = 1;
    transport_params.initial_max_streams_uni = 1;
    transport_params.active_connection_id_limit = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT; // or use a custom value >= default
    */
    
    ngtcp2_transport_params_default(&transport_params);
    transport_params.initial_max_streams_uni = 3;
    transport_params.initial_max_stream_data_bidi_local = 128 * 1024;
    transport_params.initial_max_data = 1024 * 1024;
    // TODO : generate random numbers here using wolfssl random number gen - hardcoded just to test
    /*
    ngtcp2_cid dcid, scid;
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN; 
    uint8_t hardcoded_dcid[NGTCP2_MIN_INITIAL_DCIDLEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    memcpy(dcid.data, hardcoded_dcid, dcid.datalen); // Copy hardcoded values into dcid.data
    scid.datalen = 8; 
    uint8_t hardcoded_scid[8] = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    memcpy(scid.data, hardcoded_scid, scid.datalen);
    */

    printf("connection init done, attempting to create connection\n");

    // allocate memory for conn object - this object will represent a quic connection 
    // this doesnt work right now cuz ngtcp2_conn struct is not visible from here so the size is unknown - fix this 
    printf("testing malloc with 10 bytes\n");
    char *test = (char *)malloc(10);
    printf("10 bytes worked\n");
    
    printf("malloc for ngtcp2_conn object\n");
    ngtcp2_conn *conn = (ngtcp2_conn *)malloc(500);
    printf("conn object memory allocated successfully\n");

    // Create the ngtcp2 connection
    printf("populating conn object created\n");
    rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &transport_params, NULL, NULL);
    if (rv != 0) {
        printf("Failed to initialize ngtcp2 connection\n");
        return -1;
    }

    printf("ngtcp2 connection initialized successfully.\n");
    return 0;
}

void quic_client_cleanup(void) {
    if (conn != NULL) {
        ngtcp2_conn_del(conn);
    }
}
