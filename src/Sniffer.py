import psutil
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics


class Sniffer:

    counter = PacketCounter()
    flow_meter = FlowMeterMetrics(output_mode="flow")
    packet_data = []

    def __init__(self, interfaces=None):

        self.ifaces = []

        if interfaces is None:
            iface_dict = psutil.net_if_stats()
            for key, value in iface_dict.items():
                if (key != 'lo') and (value.isup is True):
                    self.ifaces.append(key)

        else:
            self.ifaces = interfaces

        print(self.ifaces)

    def run(self):

        sniffer = AsyncSniffer(iface=self.ifaces, prn=self.process_packet, store=False)
        sniffer.start()
        sniffer.join()

    def process_packet(self, pkt):
        if IP not in pkt:
            return

        if self.counter.get_packet_count_total() == 0:
            self.counter.set_start_time(pkt.time)

        self.counter.packet_count_total += 1

        if (TCP in pkt) or (UDP in pkt):
            flow, direction = self.flow_meter.process_packet(pkt)
            flow_metrics = flow.get_data(pkt, direction)

            print([*flow_metrics.values()])

    