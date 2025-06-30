from tcp_ack import TcpAckScan
from tcp_fin import TcpFinScan
from tcp_null import TcpNullScan
from tcp_syn import TcpSynScan
import sys

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(f'Utilisation : python {sys.argv[0]} ip start_port end_port')
        sys.exit(1)

    ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    tcp_ack_scan = TcpAckScan(ip, start_port, end_port)
    tcp_ack_scan.run()
    tcp_ack_scan.save_results_to_json('tcp_ack_scan_results.json')
    print(tcp_ack_scan)

    tcp_syn_scan = TcpSynScan(ip, start_port, end_port)
    tcp_syn_scan.run()
    tcp_syn_scan.save_results_to_json('tcp_syn_scan_results.json')
    print(tcp_syn_scan)


    tcp_fin_scan = TcpFinScan(ip, start_port, end_port)
    tcp_fin_scan.run()
    tcp_fin_scan.save_results_to_json('tcp_fin_scan_results.json')
    print(tcp_fin_scan)

    tcp_null_scan = TcpNullScan(ip, start_port, end_port)
    tcp_null_scan.run()
    tcp_null_scan.save_results_to_json('tcp_null_scan_results.json')
    print(tcp_null_scan)