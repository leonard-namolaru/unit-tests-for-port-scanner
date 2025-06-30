from port_scan import PortScan
from tcp_scan import TcpScan
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TcpAckScan(PortScan):
    """
    La méthode de scan TCP ACK permet de vérifier si un port est filtré ou non.
    """

    def __init__(self, dst: str, start_port: int, end_port: int, timeout: int = 1):
        super().__init__(dst, start_port, end_port, timeout)

    def _create_packet(self, port: int):
        ip_packet = IP(dst=self._dst)
        ack_tcp_packet = TCP(sport=55555, dport=port, flags='A', seq=0)
        return ip_packet / ack_tcp_packet

    def _test_response(self, response: Packet | None) -> dict[str, str]:
        """
        La méthode _test_response() reçoit en argument une réponse reçue après l'envoi d'un
        paquet créé à l'aide de la méthode _create_packet(). Il s'agit donc d'une instance
        de la classe Packet de la bibliothèque scapy, ou None si rien n'a été reçu.
        """
        response_analyse = dict()

        # response is not None and response.haslayer(TCP) :
        #   <=> Si une réponse a été reçue et si cette réponse est un paquet TCP
        # response.getlayer(TCP).flags & TcpScan.RST :
        #   <=> Vérifier si le flag RST (Reset) est activé
        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags & TcpScan.RST:
            response_analyse['state'] = 'unfiltered'
        else:
            # Si aucun paquet TCP n'est reçu en réponse au paquet ACK, cela signifie que le port est filtré
            response_analyse['state'] = 'filtered'

        return response_analyse