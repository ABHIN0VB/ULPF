import asyncio
import logging

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, process_pipeline):
        self.process_pipeline = process_pipeline

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        raw_msg = data.decode('utf-8', errors='ignore').strip()
        metadata = {'source_ip': addr[0]}
        self.process_pipeline(raw_msg, metadata)

async def start_syslog_server(process_pipeline, host='0.0.0.0', port=5514):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(process_pipeline),
        local_addr=(host, port)
    )
    logging.info(f"Syslog UDP server listening on {host}:{port}")
    try:
        await asyncio.sleep(3600*24*365) # keep alive
    finally:
        transport.close()
