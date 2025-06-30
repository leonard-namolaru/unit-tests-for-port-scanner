from abc import ABC, abstractmethod  # Abstract Base Classes (ABCs)
from time import sleep
import json
from scapy.packet import Packet
from scapy.sendrecv import sr1
from threading import Thread


class PortScan(ABC):
    def __init__(self, dst: str, start_port: int, end_port: int, timeout: int = 1):
        self._dst = dst
        self._start_port = start_port
        self._end_port = end_port
        self._timeout = timeout

        self._packets: dict[int, [Packet | None, Packet | None]] = dict((port, [None, None]) for port
                                                                        in range(self._start_port, self._end_port))
        self._results: dict[int, dict[str, str]] = dict((port, dict()) for port
                                                        in range(self._start_port, self._end_port))

    @abstractmethod
    def _create_packet(self, port: int) -> Packet:
        pass

    @abstractmethod
    def _test_response(self, response: Packet | None) -> dict[str, str]:
        pass

    def _test_port(self, port: int, attempt_number: int = 0):
        packet = self._create_packet(port)
        response = sr1(packet, timeout=self._timeout, verbose=0)
        # if response is None and attempt_number < 5:
        #    sleep(2 ** attempt_number)
        #   self._test_port(port, attempt_number + 1)
        self._packets[port] = [packet, response]
        self._results[port] = self._test_response(response)

    def run(self):
        threads: list[Thread] = []
        for port in range(self._start_port, self._end_port + 1):
            thread = Thread(target=self._test_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    @property
    def results(self):
        return self._results
    
    def save_results_to_json(self, filename: str):
        with open(filename, 'w') as file:
            json.dump(self._results, file, indent=4)

    def __str__(self):
        string = f'{self.__module__.replace("_", " ")} \n'
        for port, port_analyse in self.results.items():
            string += str(port) + '\t' + port_analyse['state'] + '\n'
        return string
