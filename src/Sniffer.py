import keras.src.ops
import psutil
import tensorflow_decision_forests as tfdf
import tensorflow as tf
import pandas as pd
import numpy as np
from collections import OrderedDict, deque

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.metadata.input_layer import InputLayer
from src.utils import pretty_time_delta, normalize

MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/neural_network/deep_neural_network/DeepNeuralNet'


# MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/neural_network/logistic_regression/LogisticRegression'
# MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/decision_tree/random_forest/RandomForestModel'
# MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/decision_tree/boosted_tree/BoostedTreesModel'


class Sniffer:
    counter = PacketCounter()
    flow_meter = FlowMeterMetrics(output_mode="flow")
    model = tf.keras.layers.TFSMLayer(MODEL_FILEPATH, call_endpoint="serving_default")
    input_layer = InputLayer()
    packet_queue = deque(maxlen=200)

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

        try:
            sniffer = AsyncSniffer(iface=self.ifaces, prn=self.process_packet, store=False)
            sniffer.start()
            sniffer.join()

        except KeyboardInterrupt:
            elapsed_time = time.time() - self.counter.get_start_time()
            print(
                "\nSniffed %d packets in %s" % (self.counter.get_packet_count_total(), pretty_time_delta(elapsed_time)))
            raise KeyboardInterrupt

    def process_packet(self, pkt):

        if self.counter.get_packet_count_total() == 0:
            self.counter.set_start_time(pkt.time)

        self.counter.packet_count_total += 1

        if IP not in pkt:
            return

        if (TCP in pkt) or (UDP in pkt):

            self.counter.packet_count_preprocessed += 1

            flow, direction = self.flow_meter.process_packet(pkt)
            packet_data = flow.get_data(pkt, direction)
            self.packet_queue.appendleft(
                {x: y for x, y in packet_data.items() if x not in self.input_layer.exclude_features}
            )

            print(len(self.packet_queue))
            if self.counter.get_packet_count_preprocessed() > 5:
                pass
                # input = keras.layers.Concatenate(axis=0)(self.packet_queue[len(self.packet_queue) - 1].values())

                # input = self.flow_metrics.to_numpy()
                # if MODEL_FILEPATH.__contains__('neural_network'):
                # input = np.apply_along_axis(func1d=normalize, axis=0, arr=input, method='zscore')
                # input = [np.split(row, self.flow_metrics.shape[1]) for row in input]

                input = self.packet_queue[len(self.packet_queue) - 1]

                print(self.model(input))
