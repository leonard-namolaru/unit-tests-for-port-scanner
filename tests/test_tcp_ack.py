from tests.conftest import exec_ssh_command_with_error_handling
from src.port_scanner import tcp_ack


def test_tcp_ack_1(host, ssh_connection_after_iptables_reset):
    port_number = 22
    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'unfiltered'


def test_tcp_ack_2(host, ssh_connection_after_iptables_reset):
    port_number = 21
    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'unfiltered'


def test_tcp_ack_3(host, ssh_connection_after_iptables_reset):
    port_number = 22

    # iptables [-m name [module-options...]]
    # [!] --syn : uniquement les paquets TCP avec le bit SYN défini et les bits ACK, RST et FIN effacés.
    # Bloquer de tels paquets empêchera les connexions TCP entrantes, avec "!" le sens de l'option est inversé.

    # Les options -m ou --match : pour utiliser un module
    # après cela, diverses options de ligne de commande supplémentaires deviennent disponibles.

    # L'extension "state" : [!] --state INVALID, ESTABLISHED, NEW, RELATED ou UNTRACKED
    # NEW : Le paquet a démarré une nouvelle connexion ou est associé à une connexion qui n'a pas vu de paquets dans
    # les deux sens.
    # Source : https://ipset.netfilter.org/iptables-extensions.man.html
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"! --syn -m state --state NEW -j DROP")

    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'filtered'


def test_tcp_ack_4(host, ssh_connection_after_iptables_reset):
    port_number = 21
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport "
                                         f"{port_number} ! --syn -m state --state NEW -j DROP")

    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'filtered'


def test_tcp_ack_5(host, ssh_connection_after_iptables_reset):
    port_number = 22
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"! --syn -m state --state NEW -j REJECT")

    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'filtered'


def test_tcp_ack_6(host, ssh_connection_after_iptables_reset):
    port_number = 21
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"! --syn -m state --state NEW -j REJECT")

    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'filtered'

def test_tcp_ack_7(host, ssh_connection_after_iptables_reset):
    port_number = 21
    # [!] --tcp-flags mask comp
    # Le premier argument (mask) correspond aux flags que nous devons examiner
    # Le deuxième argument (comp) correspond aux flags qui doivent être définis.
    # Les flags sont : SYN ACK FIN RST URG PSH ALL NONE.
    # Source : https://ipset.netfilter.org/iptables-extensions.man.html
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"--tcp-flags ALL ACK -j DROP")

    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'filtered'

def test_tcp_ack_8(host, ssh_connection_after_iptables_reset):
    port_number = 21
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number}"
                                         f" --tcp-flags ALL ACK -j REJECT")

    tcp_ack_scan = tcp_ack.TcpAckScan(host, port_number, port_number)
    tcp_ack_scan.run()
    assert tcp_ack_scan.results[port_number]['state'] == 'filtered'
