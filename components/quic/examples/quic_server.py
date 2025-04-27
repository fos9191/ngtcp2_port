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
            print(f"received data on stream {event.stream_id}: {event.data.decode()}")
            
            data = b"hello from QUIC server!"
            data = struct.pack("!H", len(data)) + data
            self._quic.send_stream_data(event.stream_id, data, end_stream=False)
            print("sent data back")
            self.transmit()
        
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
