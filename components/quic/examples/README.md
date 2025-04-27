# Running examples

## Running / altering test streams example

The repository is setup to run the QUIC client to open multiple bidirectional streams and transmit and receive data over streams. If you wish to run unidirectional streams or alter the amount of streams, follow the following instructions:

1. Navigate to the /main/ngtcp2_port.c file. In the app_main_logic function, change the test_streams call to use either 0 or 1 as the second parameter to the test_streams call. 0 for unidirectional, 1 for bidirectional streams to be opened. E.g. for bidirectional streams use "test_streams(main_task_handle, 1, num_streams);" and for unidirectional use test_streams(main_task_handle, 0, num_streams);"
2. The number of streams can be altered in the same function call to test_streams via the num_streams variable. 

The TLS certificate and keys that are hardcoded into the examples should allow the creation of a QUIC connection. Given the certificate is self signed, these are purely for demonstrational purposes. See last section for instructions on generating new TLS certificates. 

## Running throughput test

To run the throughput test, uncommonent the "// throughput(main_task_handle, 1, num_streams);" line in /main/ngtcp2_port.c. This will call the throughput example. For the server side, run ```python3 throughput_test.py`` so that the server measures how fast the data is arriving. This should give results similar to those seen in the dissertation. 



## Generating new TLS certificates and keys

If you wish to generate your own certificates, the following instructions can be followed:

CA certificate (enter details when prompted):  
```bash
openssl req -x509 -new -nodes -keyout ca.key -out ca.crt -days 365
```

Server private key:  
```bash
openssl genpkey -algorithm RSA -out server.key
```

Server certificate:  
```bash
openssl req -new -key server.key -out server.csr
```
To create a server signing request and use this to issue a signed certificate using:  
```bash
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
```

After generating these, copy them into the examples (test_streams.c or throughput.c) as shown with the current keys / certificates. 

