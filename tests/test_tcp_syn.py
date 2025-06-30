from tests.conftest import exec_ssh_command_with_error_handling
from src.port_scanner import tcp_syn


def test_tcp_syn_1(host, ssh_connection_after_iptables_reset):
    port_number = 21
    tcp_syn_result = tcp_syn.TcpSynScan(host, port_number, port_number)
    tcp_syn_result.run()

    assert tcp_syn_result.results[port_number]['state'] == 'closed'


def test_tcp_syn_2(host, ssh_connection_after_iptables_reset):
    port_number = 22

    tcp_syn_result = tcp_syn.TcpSynScan(host, port_number, port_number)
    tcp_syn_result.run()

    assert tcp_syn_result.results[port_number]['state'] == 'open'


def test_tcp_syn_3(host, ssh_connection_after_iptables_reset):
    port_number = 80
    exec_ssh_command_with_error_handling(ssh_connection_after_iptables_reset,
                                         f"sudo iptables -A INPUT -p tcp --dport {port_number} "
                                         f"-j REJECT")

    tcp_syn_result = tcp_syn.TcpSynScan(host, port_number, port_number)
    tcp_syn_result.run()

    assert tcp_syn_result.results[port_number]['state'] == 'filtered'
