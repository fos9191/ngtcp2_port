import asyncio
import time
import struct
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, ConnectionIdIssued, ConnectionTerminated, ProtocolNegotiated
from aioquic.asyncio.protocol import QuicConnectionProtocol


class QUICServer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data_received = 0
        self.start_time = 0 
        self.target_data_size = 5120 * 4
        self.stream_id = None

    def connection_made(self, transport):
        super().connection_made(transport)
        self.transport = transport  

    def quic_event_received(self, event):        
        if isinstance(event, HandshakeCompleted):
            print("handshake complete")
            self.stream_id = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(self.stream_id, b"Hello from QUIC server!\n")
            self.transmit()

        elif isinstance(event, ConnectionTerminated):
            print("connection terminated")
            self._quic.close(error_code=0)
            self.transmit()  
            self.transport.close()  
            self.transmit()
            
        elif isinstance(event, StreamDataReceived):            
            data = event.data
            data_size = len(data)
            self.data_received += data_size

            current_time = time.time()

            if not hasattr(self, "packet_count"):
                self.packet_count = 0
            if not hasattr(self, "one_mb_logged"):
                self.one_mb_logged = False
            if not hasattr(self, "one_mb_start_time"):
                self.one_mb_start_time = current_time
            if self.start_time == 0:
                self.start_time = current_time

            self.packet_count += 1

            # print data rate 
            if self.packet_count % 10 == 0:
                elapsed_time = current_time - self.start_time
                data_rate_kbps = (self.data_received / 1024) / elapsed_time  # convert to KB/s
                print(f"[Packet {self.packet_count}] Data rate: {data_rate_kbps:.2f} KB/s")

            # check for 1mb 
            ONE_MB = 5 * 1000
            if not self.one_mb_logged and self.data_received >= ONE_MB:
                time_gone = current_time - self.one_mb_start_time
                print(f"received 1 MB in {time_gone:.2f} seconds")
                self.one_mb_logged = True

            self.transmit()

            # data = b"hello from QUIC server!"
            # data = struct.pack("!H", len(data)) + data
            # self._quic.send_stream_data(event.stream_id, data, end_stream=False)
            # print("sent data back")
        
        elif isinstance(event, ConnectionIdIssued):
            print("new CID")
            # when a new CID is issued, open a new stream
            self.stream_id = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(self.stream_id, b"New connection established, sending data!\n")
            self.transmit()
            
        elif isinstance(event, ProtocolNegotiated):
            print("ignoring protocol negotiation")
        else:
            print(f"Unhandled event type: {type(event).__name__}") 

    def transmit(self):
        """Send QUIC packets."""
        if self.transport and self._quic:
            now = time.time()  
            for data, addr in self._quic.datagrams_to_send(now=now):
                self.transport.sendto(data, addr)

async def main():
    config = QuicConfiguration(is_client=False)
    config.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")

    print("starting QUIC server with addr:port - 0.0.0.0:4433")
    await serve("0.0.0.0", 4433, configuration=config, create_protocol=QUICServer)
    
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
