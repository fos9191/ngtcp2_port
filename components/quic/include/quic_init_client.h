// quic_client.h
#ifndef QUIC_INIT_CLIENT_H
#define QUIC_INIT_CLIENT_H

ngtcp2_path set_ngtcp2_path(const char *local_ip, const char *remote_ip, uint16_t local_port, uint16_t remote_port);
int quic_client_init(ngtcp2_path path);
void quic_client_cleanup(void);

#endif // QUIC_INIT_CLIENT_H
