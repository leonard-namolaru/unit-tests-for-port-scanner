from port_scan import PortScan
from tcp_scan import TcpScan
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TcpFinScan(PortScan):
    def __init__(self, dst: str, start_port: int, end_port: int, timeout: int = 1):
        super().__init__(dst, start_port, end_port, timeout)

    def _create_packet(self, port: int):
        ip_packet = IP(dst=self._dst)
        fin_tcp_packet = TCP(sport=55555, dport=port, flags='F')
        return ip_packet / fin_tcp_packet

    def _test_response(self, response: Packet | None) -> dict[str, str]:
        response_analysis = {}
        if response is not None and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags & TcpScan.RST:
                response_analysis['state'] = 'closed'
            else:
                response_analysis['state'] = 'open|filtered'
        else:
            response_analysis['state'] = 'open|filtered'
        return response_analysis
