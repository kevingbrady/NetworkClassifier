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

            self.packet_data.append([
                flow_metrics["src_ip"],
                flow_metrics["dst_ip"],
                flow_metrics["src_port"],
                flow_metrics["dst_port"],
                flow_metrics["protocol"],
                flow_metrics["pkt_length"],
                flow_metrics["info"],
                flow_metrics["timestamp"],
                flow_metrics["flow_duration"],
                flow_metrics["flow_byts_s"],
                flow_metrics["flow_pkts_s"],
                flow_metrics["fwd_pkts_s"],
                flow_metrics["bwd_pkts_s"],
                flow_metrics["tot_fwd_pkts"],
                flow_metrics["tot_bwd_pkts"],
                flow_metrics["totlen_fwd_pkts"],
                flow_metrics["totlen_bwd_pkts"],
                flow_metrics["fwd_pkt_len_max"],
                flow_metrics["fwd_pkt_len_min"],
                flow_metrics["fwd_pkt_len_mean"],
                flow_metrics["fwd_pkt_len_std"],
                flow_metrics["bwd_pkt_len_max"],
                flow_metrics["bwd_pkt_len_min"],
                flow_metrics["bwd_pkt_len_mean"],
                flow_metrics["bwd_pkt_len_std"],
                flow_metrics["pkt_len_max"],
                flow_metrics["pkt_len_min"],
                flow_metrics["pkt_len_mean"],
                flow_metrics["pkt_len_std"],
                flow_metrics["pkt_len_var"],
                flow_metrics["fwd_header_len"],
                flow_metrics["bwd_header_len"],
                flow_metrics["fwd_seg_size_min"],
                flow_metrics["fwd_act_data_pkts"],
                flow_metrics["flow_iat_mean"],
                flow_metrics["flow_iat_max"],
                flow_metrics["flow_iat_min"],
                flow_metrics["flow_iat_std"],
                flow_metrics["fwd_iat_tot"],
                flow_metrics["fwd_iat_max"],
                flow_metrics["fwd_iat_min"],
                flow_metrics["fwd_iat_mean"],
                flow_metrics["fwd_iat_std"],
                flow_metrics["bwd_iat_tot"],
                flow_metrics["bwd_iat_max"],
                flow_metrics["bwd_iat_min"],
                flow_metrics["bwd_iat_mean"],
                flow_metrics["bwd_iat_std"],
                flow_metrics["fwd_psh_flags"],
                flow_metrics["bwd_psh_flags"],
                flow_metrics["fwd_urg_flags"],
                flow_metrics["bwd_urg_flags"],
                flow_metrics["fin_flag_cnt"],
                flow_metrics["syn_flag_cnt"],
                flow_metrics["rst_flag_cnt"],
                flow_metrics["psh_flag_cnt"],
                flow_metrics["ack_flag_cnt"],
                flow_metrics["urg_flag_cnt"],
                flow_metrics["ece_flag_cnt"],
                flow_metrics["down_up_ratio"],
                flow_metrics["pkt_size_avg"],
                flow_metrics["init_fwd_win_byts"],
                flow_metrics["init_bwd_win_byts"],
                flow_metrics["active_max"],
                flow_metrics["active_min"],
                flow_metrics["active_mean"],
                flow_metrics["active_std"],
                flow_metrics["idle_max"],
                flow_metrics["idle_min"],
                flow_metrics["idle_mean"],
                flow_metrics["idle_std"],
                flow_metrics["fwd_byts_b_avg"],
                flow_metrics["fwd_pkts_b_avg"],
                flow_metrics["bwd_byts_b_avg"],
                flow_metrics["bwd_pkts_b_avg"],
                flow_metrics["fwd_blk_rate_avg"],
                flow_metrics["bwd_blk_rate_avg"]
            ])

            print(self.packet_data[-1])

    