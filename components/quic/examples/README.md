# Running examples

### Generating TLS certificates and keys

NOT TESTED YET !

CA certificate: openssl req -x509 -new -nodes -keyout ca.key -out ca.crt -days 365 \
Enter details when prompted.

Server private key: openssl genpkey -algorithm RSA -out server.key

Server certificate: openssl req -new -key server.key -out server.csr \
To create a server signing request and use this to issue a signed certificate using: \
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365


