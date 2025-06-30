from tests.conftest import exec_ssh_command_with_error_handling
from src.port_scanner import tcp_fin


def test_tcp_fin_1(host, ssh_connection_after_iptables_reset):
    port_number = 22
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"--tcp-flags FIN FIN -j REJECT --reject-with tcp-reset")

    tcp_fin_scan = tcp_fin.TcpFinScan(host, port_number, port_number)
    tcp_fin_scan.run()
    assert tcp_fin_scan.results[port_number]['state'] == 'closed'


def test_tcp_fin_2(host, ssh_connection_after_iptables_reset):
    port_number = 21
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"--tcp-flags FIN FIN -j DROP")

    tcp_fin_scan = tcp_fin.TcpFinScan(host, port_number, port_number)
    tcp_fin_scan.run()
    assert tcp_fin_scan.results[port_number]['state'] == 'open|filtered'


def test_tcp_fin_3(host, ssh_connection_after_iptables_reset):
    port_number = 21
    tcp_fin_scan = tcp_fin.TcpFinScan(host, port_number, port_number)
    tcp_fin_scan.run()

    assert tcp_fin_scan.results[21]['state'] == 'closed'


def test_tcp_fin_4(host, ssh_connection_after_iptables_reset):
    port_number = 22
    tcp_fin_scan = tcp_fin.TcpFinScan(host, port_number, port_number)
    tcp_fin_scan.run()

    assert tcp_fin_scan.results[22]['state'] == 'open|filtered'
