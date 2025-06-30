from port_scan import PortScan
from tcp_scan import TcpScan
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TcpNullScan(PortScan):

    def __init__(self, dst: str, start_port: int, end_port: int, timeout: int = 1):
        super().__init__(dst, start_port, end_port, timeout)

    def _create_packet(self, port: int) -> Packet:
        return IP(dst=self._dst) / TCP(dport=port, flags=TcpScan.NULL)

    def _test_response(self, response: Packet | None) -> dict[str, str]:
        if response is None:
            return {'state': 'open|filtered'}
        elif response.haslayer(TCP) and response.getlayer(TCP).flags & TcpScan.RST:
            return {'state': 'closed'}
        else:
            return {'state': 'filtered'}

