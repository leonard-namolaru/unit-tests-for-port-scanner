from tests.conftest import exec_ssh_command_with_error_handling
from src.port_scanner import tcp_null


def test_tcp_null_1(host, ssh_connection_after_iptables_reset):
    port = 21
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port} "
                                         f"-j REJECT --reject-with tcp-reset")

    tcp_null_scan = tcp_null.TcpNullScan(host, port, port)
    tcp_null_scan.run()
    assert tcp_null_scan.results[port]['state'] == 'closed'


def test_tcp_null_2(host, ssh_connection_after_iptables_reset):
    port = 22
    tcp_null_scan = tcp_null.TcpNullScan(host, port, port)
    tcp_null_scan.run()
    assert tcp_null_scan.results[port]['state'] == 'open|filtered'


def test_tcp_null_3(host, ssh_connection_after_iptables_reset):
    port = 21
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port} -j REJECT")
    tcp_null_scan = tcp_null.TcpNullScan(host, port, port)
    tcp_null_scan.run()
    assert tcp_null_scan.results[port]['state'] == 'filtered'


def test_tcp_null_4(host, ssh_connection_after_iptables_reset):
    port = 21
    tcp_null_scan = tcp_null.TcpNullScan(host, port, port)
    tcp_null_scan.run()
    assert tcp_null_scan.results[port]['state'] == 'closed'
