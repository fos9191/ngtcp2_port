/*
 * ngtcp2
 *
 * Copyright (c) 2021 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <esp_log.h>
#include "esp_event.h"
#include <esp_timer.h>

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h> 

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

// must include wolfssl/settings.h before any other wolfssl files
#include <wolfssl/wolfcrypt/settings.h> 
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

#ifndef WOLFSSL_ESPIDF
    #warning "Problem with wolfSSL user_settings."
    #warning "Check components/wolfssl/include"
#endif

//#include <ev.h>

#define REMOTE_HOST "172.20.10.3"
#define REMOTE_PORT "4433"
#define ALPN "\x2h3"

#define TEST_UDP_IP "172.20.10.3"
#define TEST_UDP_PORT "4433"
//#define MESSAGE "GET /\r\n"

static const char *TAG = "quic_client_init";

// define esp event base for event management
ESP_EVENT_DEFINE_BASE(MY_EVENT_BASE);
#define MY_EVENT_ID_READ 0


/*
 * Example 1: Handshake with www.google.com
 *
 * #define REMOTE_HOST "www.google.com"
 * #define REMOTE_PORT "443"
 * #define ALPN "\x2h3"
 *
 * and undefine MESSAGE macro.
 */
#include "esp_heap_caps.h"



static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  //used to check timestamp works
  //fprintf(stderr, "Timestamp: %lld seconds, %ld nanoseconds\n", tp.tv_sec, tp.tv_nsec);
  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}


static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    //fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    printf(stderr);
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    ESP_LOGI(TAG, "Socket created successfully with fd: %d\n", fd);
    break;
  }

  if (fd == -1) {
    goto end;
  }

  *paddrlen = rp->ai_addrlen;
  memcpy(addr, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);

  return fd;
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen,
                        int fd, const struct sockaddr *remote_addr,
                        size_t remote_addrlen) {
  socklen_t len;

  if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return -1;
  }

  len = *plocal_addrlen;

  if (getsockname(fd, local_addr, &len) == -1) {
    fprintf(stderr, "getsockname: %s\n", strerror(errno));
    return -1;
  }

  *plocal_addrlen = len;

  return 0;
}

struct client {
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  WOLFSSL_CTX *ssl_ctx;
  WOLFSSL *ssl;
  ngtcp2_conn *conn;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } stream;

  ngtcp2_ccerr last_error;
  
  uint64_t timestamp_us;
};

static int numeric_host_family(const char *hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

#include <stdio.h>
#include <time.h>

void print_system_time() {
    time_t now;
    struct tm timeinfo;

    time(&now);
    localtime_r(&now, &timeinfo);

    printf("Current time: %04d-%02d-%02d %02d:%02d:%02d\n",
           timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
           timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}


void send_udp_burst(int sockfd, struct sockaddr_in *server_addr) {
  const char *msg = "test udp packets";
  for (int i = 0; i < 3; i++) { 
      sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr *)server_addr, sizeof(*server_addr));
      printf("sent a udp packet\n");
      vTaskDelay(pdMS_TO_TICKS(2500)); // delay between packets
  }

  ESP_LOGI(TAG, "sent 5 udp packets");
}

void udp_flush() {
  // sends udp packets to server specified by TEST_UDP_PORT and TEST_UDP_IP
  int sockfd;
  struct sockaddr_in server_addr ;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
      perror("Socket creation failed");
      return;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(TEST_UDP_PORT);
  inet_pton(AF_INET, TEST_UDP_IP, &server_addr.sin_addr);

  send_udp_burst(sockfd, &server_addr);

  close(sockfd);
}

static int client_ssl_init(struct client *c) {
  ESP_LOGI(TAG, "WolfSSL client init");
  c->ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
  if (!c->ssl_ctx) {
    //fprintf(stderr, "SSL_CTX_new: %s\n",ERR_error_string(ERR_get_error(), NULL));
    fprintf(stderr, "error with wolfSSL_CTX_new\n");
    return -1;
  }

  //load the CA cert from google.com - got using openssl 
  const char promCert[] = \
          "-----BEGIN CERTIFICATE-----\n" \
          "MIID+zCCAuOgAwIBAgIUB9WQyCsV5x+JucBM5tC4HwfpUSMwDQYJKoZIhvcNAQEL\n" \
          "BQAwgYwxCzAJBgNVBAYTAklFMRMwEQYDVQQIDApTb21lLVN0YXRlMQ8wDQYDVQQH\n" \
          "DAZEdWJsaW4xITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEMMAoG\n" \
          "A1UEAwwDZm9zMSYwJAYJKoZIhvcNAQkBFhdmaW9ubmFub3MyMDAwQGdtYWlsLmNv\n" \
          "bTAeFw0yNTAyMDYxMjAwMDJaFw0yNjAyMDYxMjAwMDJaMIGMMQswCQYDVQQGEwJJ\n" \
          "RTETMBEGA1UECAwKU29tZS1TdGF0ZTEPMA0GA1UEBwwGRHVibGluMSEwHwYDVQQK\n" \
          "DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDDAKBgNVBAMMA2ZvczEmMCQGCSqG\n" \
          "SIb3DQEJARYXZmlvbm5hbm9zMjAwMEBnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEB\n" \
          "AQUAA4IBDwAwggEKAoIBAQCswdjOeGosJScHOdmv+U2goxWfRXziMcjhYjn782HR\n" \
          "x9i0eb32V2q8UjWVszSZxF+NuRLZvKsGKOf2yd4XukkObfqrzf8gwLuskEpP1dyt\n" \
          "YrKAkIDAXUDv4obeapuesgYnoiH1yg8h9eoYAkVwu6xPrdvI+pBEznUpyS204Y1i\n" \
          "acm1tbZMkrXIkCanRW+Rsbf43c1wNOaepbtSlVtEfvngAFaMjdPAU6athOHu2L8S\n" \
          "lWqyrxvD1MHiJ17OLLYueF+lnk0gyaFmwIQ8/7h/kXfKcJ9UI6basEjw2cZgymUB\n" \
          "KIKC1F/7W3rW3iEo1omksS0wm7Q1qCgqoRhtSaWIu9udAgMBAAGjUzBRMB0GA1Ud\n" \
          "DgQWBBTPy++v3u3w62lgaEqw6762ZRQrdTAfBgNVHSMEGDAWgBTPy++v3u3w62lg\n" \
          "aEqw6762ZRQrdTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCs\n" \
          "FyGAimReycGBC0M5XojBNVwHCKTpPo8qcH/jyP9FNV+dsKAxqBuRfYibOdpNQxHb\n" \
          "jZpxWSytITZfecwIlLuqVJJA4UcFa4DjTWXQxnz9soeElZSYCBdxOLn+CFGInGJA\n" \
          "+v74DJI5+bvEK9F4Q8Az4FVfeb2w6QxjB5sSmuXASRh4Xlf29/Z2Yj1jw1Qv73a3\n" \
          "6/g47M/wkEJhfP/FuihhQYAluaGkNlN9wE6NMd9GohMX3ynB2K5E+ut4zO4Qtj3N\n" \
          "Jyt5uNXU2rL7FiEu3OOsJfoSog6F1zjW1zC2yR1MNsci9j8n34xvSFqcgJGbHRlF\n" \
          "bo2ViNrwZTbhuJbv1wxI\n" \
          "-----END CERTIFICATE-----\n";
          
  print_system_time();
  if (wolfSSL_CTX_load_verify_buffer(c->ssl_ctx, (const byte*)promCert, strlen(promCert), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
      fprintf(stderr, "error loading CA certificate\n");
      return -1;
  }
  printf("FP_MAX_BITS is set to: %d\n", FP_MAX_BITS);
  /*
  int ret = wolfSSL_CTX_use_certificate_chain_file(ctx, "path/to/your/certificate_chain.pem");
    if (ret != WOLFSSL_SUCCESS) {
        printf("Error loading certificate chain\n");
        wolfSSL_CTX_free(ctx);
        return -1;
    }
  */
  
  if (ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx) != 0) {
    fprintf(stderr, "ngtcp2_crypto_wolfssl_configure_client_context failed\n");
    return -1;
  }

  c->ssl = wolfSSL_new(c->ssl_ctx);
  if (!c->ssl) {
    //fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    fprintf(stderr, "error with wolfSSL_new\n");
    return -1;
  }

  SSL_set_app_data(c->ssl, &c->conn_ref);
  SSL_set_connect_state(c->ssl);
  
  SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
  if (!numeric_host(REMOTE_HOST)) {
    SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
  }   
  
  return 0;
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

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {
  ngtcp2_path path = {
    {
      (struct sockaddr *)local_addr,
      local_addrlen,
    },
    {
      (struct sockaddr *)remote_addr,
      remote_addrlen,
    },
    NULL,
  };
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
  ngtcp2_transport_params params;
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

  ngtcp2_settings_default(&settings);

  settings.initial_ts = timestamp();
  settings.log_printf = log_printf;

  ngtcp2_transport_params_default(&params);

  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                           &callbacks, &settings, &params, NULL, c);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  return 0;
}

static int client_read(struct client *c) {
  uint8_t buf[65536];
  struct sockaddr_storage addr;
  struct iovec iov = {buf, sizeof(buf)};
  struct msghdr msg = {0};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  
  for (;;) {
    msg.msg_namelen = sizeof(addr);

    nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = msg.msg_name;
    printf("calling ngtcp2_conn_read_pkt\n");
    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                              timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      if (!c->last_error.error_code) {
        if (rv == NGTCP2_ERR_CRYPTO) {
          ngtcp2_ccerr_set_tls_alert(
            &c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
        } else {
          ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
        }
      }
      return -1;
    }
  }

  return 0;
}

static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {
  struct iovec iov = {(uint8_t *)data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    fprintf(stderr, "sendmsg: %s\n", strerror(errno));

    return -1;
  }

  return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;

  return 0;
}

static int client_write_streams(struct client *c) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1452];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }
    
    nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);
    
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_WRITE_MORE:
        c->stream.nwrite += (size_t)wdatalen;
        continue;
      default:
        fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                ngtcp2_strerror((int)nwrite));
        ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
        return -1;
      }
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0) {
      c->stream.nwrite += (size_t)wdatalen;
    }

    if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
      break;
    }
  }

  return 0;
}


static int client_write(struct client *c) {
  ngtcp2_tstamp expiry, now;
  int64_t t;

  if (client_write_streams(c) != 0) {
    ESP_LOGE(TAG, "client_write_streams failed");
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (expiry - now) / NGTCP2_SECONDS;

  //c->timer.repeat = t;
  //esp_timer_start_once(&c->timer, t);

  return 0;
}



static int client_handle_expiry(struct client *c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}


static void client_close(struct client *c) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_in_closing_period(c->conn) ||
      ngtcp2_conn_in_draining_period(c->conn)) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(
    c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
  if (nwrite < 0) {
    fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
            ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  client_send_packet(c, buf, (size_t)nwrite);

fin:
  //ev_break(EV_DEFAULT, EVBREAK_ALL);
  return;
}

// my read_cb function to test reading from the socket
static void read_cb(struct client *c) {
    // Check if there is data to read from the client
    if (client_read(c) != 0) {
        ESP_LOGE("read_cb", "Error reading from client.");
        client_close(c);
        return;
    }

    // If reading was successful, attempt to write back to the client
    if (client_write(c) != 0) {
        ESP_LOGE("read_cb", "Error writing to client.");
        //client_close(c);
    }
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct client *c = conn_ref->user_data;
  return c->conn;
}

// this function should read from the socket (c->fd)
void socket_read_task(void *param) {
    struct client *c = (struct client *)param;
    fd_set read_fds;
    struct timeval timeout;

    if (c->fd < 0) {
        printf("Invalid file descriptor: %d\n", c->fd);
        return;
    }

    int flags = fcntl(c->fd, F_GETFL, 0);
    if (flags & O_NONBLOCK) {
        ESP_LOGI(TAG, "Socket is in non-blocking mode");
    } else {
      ESP_LOGI(TAG, "Socket is in blocking mode");
    }

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(c->fd, &read_fds);

        timeout.tv_sec = 1;  // ?? why
        timeout.tv_usec = 0;
        
        //printf("fd_isset is : %ld\n", FD_ISSET(c->fd, &read_fds));
        int ret = lwip_select(c->fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ret > 0) {
            //ESP_LOGI(TAG, "reading from socket");
            read_cb(c); // read from socket
        } 

        vTaskDelay(pdMS_TO_TICKS(100));  // delay for 10ms so that we yield to scheduler
    }

    vTaskDelete(NULL);
}

static int client_init(struct client *c) {
  struct sockaddr_storage remote_addr, local_addr;
  socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);
  memset(c, 0, sizeof(*c));

  ngtcp2_ccerr_default(&c->last_error);

  c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                      REMOTE_HOST, REMOTE_PORT);
  if (c->fd == -1) {
    return -1;
  }

  if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd,
                   (struct sockaddr *)&remote_addr, remote_addrlen) != 0) {
    return -1;
  }

  memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
  c->local_addrlen = local_addrlen;

  if (client_ssl_init(c) != 0) {
    return -1;
  }

  if (client_quic_init(c, (struct sockaddr *)&remote_addr, remote_addrlen,
                       (struct sockaddr *)&local_addr, local_addrlen) != 0) {
    return -1;
  }

  c->stream.stream_id = -1;

  c->conn_ref.get_conn = get_conn;
  c->conn_ref.user_data = c;
  
  /*
  this code initializes and starts an I/O watcher on a file descriptor (c->fd) 
  to monitor for readability. When data becomes available on this file descriptor, 
  the specified callback (read_cb) will be invoked.

  ev_io_init(&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start(EV_DEFAULT, &c->rev);

  ev_timer_init(&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;
  */

  return 0;
}


static void client_free(struct client *c) {
  ngtcp2_conn_del(c->conn);
  wolfSSL_free(c->ssl);
  wolfSSL_CTX_free(c->ssl_ctx);
}

struct sockaddr_in get_remote_addr() {
  struct sockaddr_in remote_addr;
  
  memset(&remote_addr, 0, sizeof(remote_addr));
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_port = htons(atoi(REMOTE_PORT));

  if (inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr) <= 0) {
    ESP_LOGE(TAG, "failure converting address to binary form");
    exit(EXIT_FAILURE);
  }

  return remote_addr;
}

// creates and sends data over the stream specified
int send_data(struct client * c, int64_t stream_id) {
  int count = 0;
  ngtcp2_ssize size = NULL;
  uint8_t dest_buffer[1300];
  ngtcp2_vec data;
  const char *hello_msg = "hello from client hello from client hello from client hello from client";
  size_t msg_len = strlen(hello_msg) + 1; 
  data.base = (uint8_t *)malloc(msg_len);
  memcpy(data.base, hello_msg, msg_len);
  data.len = msg_len;
  uint64_t now = timestamp();

  size = ngtcp2_conn_writev_stream(c->conn, NULL, NULL, dest_buffer, sizeof(dest_buffer), 
                                                NULL, NULL, stream_id, &data, 1, now);
  if (size < 0) {
    ESP_LOGE(TAG, "error writing to stream");
  }
  
  struct sockaddr_in remote_addr = get_remote_addr();
  
  ssize_t sent_bytes = sendto(c->fd, dest_buffer, size, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
  if (sent_bytes < 0) {
      perror("sendto failed");
      free(data.base);
      return -1;
    }

  return 0;
}

// opens a bidirectional stream
int open_bidi_stream(struct client * c, int64_t *stream_id) {
  return ngtcp2_conn_open_bidi_stream(c->conn, stream_id, NULL);
}

// opens a unidirectional stream
int open_uni_stream(struct client * c, int64_t *stream_id) {
  return ngtcp2_conn_open_uni_stream(c->conn, stream_id, NULL);
}

// opens no_streams streams of type bidi or uni - type-0 = uni. type-1 = bidi 
int open_streams(struct client * c, int64_t *stream_ids, int no_streams, int type) {
  int ret = -1;
  int (*open_stream)(struct client *, int64_t *) = NULL;
  void (*stream_funcs[2])() = {open_uni_stream, open_bidi_stream};

  if (type == 0 || type == 1) {
    open_stream = stream_funcs[type];
  } else {
    ESP_LOGE(TAG, "error picking stream type. use type = 0 for uni stream, type = 1 for bidi stream");
    return -1;
  }

  for(int i = 0; i < no_streams; i++) {
    ret = open_stream(c, &stream_ids[i]);
  }

  if (ret == 0) {
    ESP_LOGI(TAG, "successfully opened %d streams", no_streams);
    return 0;
  } else {
    ESP_LOGE(TAG, "error opening streams");
    return -1;
  }
}


int quic_init_client() {
  struct client c;

  srandom((unsigned int)timestamp());

  ESP_LOGI(TAG, "creating QUIC client");
  if (client_init(&c) != 0) {
    exit(EXIT_FAILURE);
  } 

  fd_set read_fds;
  struct timeval timeout;
  int handshake = 0;

  while (!handshake) {
    FD_ZERO(&read_fds);
    FD_SET(c.fd, &read_fds);
    
    ESP_LOGI(TAG, "starting handshake");
    if (client_write(&c) != 0) {
      exit(EXIT_FAILURE);
    } 
    vTaskDelay(pdMS_TO_TICKS(10));
    // if handshake is complete this will output 1 - rn it outputs 0
    handshake = ngtcp2_conn_get_handshake_completed(c.conn);
    ESP_LOGI(TAG, "Handshake complete check (1 = success): %d", handshake);
    
    int ret = lwip_select(c.fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ret > 0) {
        ESP_LOGI(TAG, "reading from socket");
        read_cb(&c); // read from socket
    } 
    
    vTaskDelay(pdMS_TO_TICKS(1000)); 
  }
  ESP_LOGI(TAG, "handshake finished");


  // open 5 uni streams
  int no_streams = 5;
  int64_t * stream_ids = malloc(no_streams * sizeof(int64_t));
  
  if (open_streams(&c, stream_ids, no_streams, 0) == 0) {
    ESP_LOGI(TAG, "opened %d streams", no_streams);
  } else {
    ESP_LOGE(TAG, "failed to open streams");
  }

  int64_t stream_id;
  if (open_bidi_stream(&c, &stream_id) == 0) {
    ESP_LOGI(TAG, "bidirection stream opened");
  } else {
    ESP_LOGE(TAG, "failed to open bidirectional stream");
  }
  
  if (send_data(&c, stream_id) == 0) {
    ESP_LOGI(TAG, "sent data over stream : %lld", stream_id);
  } else {
    ESP_LOGE(TAG, "failed to send data over stream : %lld", stream_id);
  }
  
 
  //client_free(&c);
  //ESP_LOGI(TAG, "client freed");

  return 0;
}
