# QUIC for ESP32
This project implements a QUIC stack for ESP32. The stack consists of LwIP, WolfSSL and a ngtcp2 port for ESP-IDF. It was developed to test the feasibility of deploying QUIC — a modern transport protocol used by HTTP/3 — on resource-constrained embedded devices. It has been developed and tested on the ESP32-WROOM-32E.

## Dissertation 

The project was developed during the completion of my Master's dissertation "Investigating QUIC for Embedded Systems". Here is the abstract from my Master’s dissertation (full report is available at [TBA]):   

Since its origin in the 1980s, the internet has transformed from a simple network for transferring
files into a medium that supports complex, real-time, and interactive applications. As a result,
there has been a growing need for transport protocols capable of meeting the demands of the
modern internet. QUIC is one such protocol and has seen widespread adoption on conventional
computing platforms. However, for embedded systems - computing devices with constraints
in terms of memory, processing power and energy consumption - its deployment is largely
unexplored.
This dissertation investigates the feasibility of deploying QUIC on a resource-constrained em-
bedded device, specifically the ESP32-WROOM-32E. The work involved creating a QUIC
implementation using LwIP, WolfSSL and ngtcp2. Deployed on the ESP32 as a QUIC client,
the implementation successfully established QUIC communication with multiple server-side
implementations.
The implementation was evaluated in terms of memory usage, goodput, power consumption,
interoperability and security. It consumed 314.95 KB of RAM and 1.41 MB of Flash, with
WolfSSL being the main contributor to memory usage. The goodput was 104.8 KB/s when
sending 1 MB of data over the connection. Power consumption was recorded at 3.735 J per
5 KB transaction. Interoperability was excellent, with successful connections established with
aioquic, ngtcp2, Google servers and quiche. Security performance was acceptable, although
a potential vulnerability to flooding attacks was identified, and mitigations were discussed.
Overall, the evaluation showed that deployment of QUIC on a higher-end embedded sys-
tem, like the ESP32, is viable. For deployment on lower-tier devices, further optimisation -
particularly regarding memory usage - would likely be necessary.

## Instructions to run
1. The ESP32 and the machine running the server must be connected to the same WiFi access point. To connect the ESP32 to the access point, enter the WiFi credentials in the /main/wifi_connect.c file where instructed. 
2. Next, find the IP address of the machine that will run the server by using the follownig commands ``ìpconfig`` (Windows), ``ìp addr`` (Linux) or ``ìfconfig`` (MacOS). Take this IP address and place it into the REMOTE_HOST macro in the test_streams.c example (see components/quic/examples). 
3. Ensure that the port number in the components/quic/examples/quic_server.py file is the same as the REMOTE_PORT macro in the example you wish to run. 
4. Run the server on the server machine by navigating to components/quic/examples and running ```python3 quic_server.py```. This should run the server and output that the server is listening on all available network interfaces. At this stage, the ESP32 can connect to the server. 
5. To run the QUIC client on the ESP32, navigate to the components/quic/examples directory in in ESP-IDF terminal an run the following command``ìdf.py -p $PORT$ flash monitor`` . This will build the project, flash it to the ESP32 and monitor the output. The PORT should be replaced with the port number of the ESP32 on the machine being flashed from. 
6. The example should run, initiating a connection and transferring some data to the server. The default option opens multiple bidirectional streams and sends data over and receives data on each stream. If you wish to use more/less or unidirectional streams, see the instructions in components/quic/examples/README.md

## System Architecture

This is an overview of the system architecture and which custom and ESP-IDF components are used.

![System Architecture](docs/images/design_overview.png)
