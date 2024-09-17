import keras.src.ops
import psutil
import tensorflow_decision_forests as tfdf
import ydf
import tensorflow as tf
import pandas as pd
import numpy as np
from collections import OrderedDict, deque

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.PacketDataNormalizer import PacketDataNormalizer
from src.metadata.input_layer import InputLayer
from src.utils import pretty_time_delta, normalize

MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/neural_network/deep_neural_network/DeepNeuralNet'
#MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/neural_network/logistic_regression/LogisticRegression'
#MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/decision_tree/random_forest/RandomForestModel'
#MODEL_FILEPATH = '/home/kgb/PycharmProjects/TensorFlowPcap/src/models/decision_tree/boosted_tree/BoostedTreesModel'


class Sniffer:
    counter = PacketCounter()
    flow_meter = FlowMeterMetrics(output_mode="flow")
    normalizer = PacketDataNormalizer()
    packet_queue = deque(maxlen=200)

    def __init__(self, interfaces=None):

        #self.model = ydf.from_tensorflow_decision_forests(MODEL_FILEPATH)
        self.model = keras.models.load_model(MODEL_FILEPATH + '.keras')
        self.input_layer = InputLayer()
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

            packet_data = self.normalizer(packet_data, self.counter.packet_count_preprocessed)

            self.packet_queue.appendleft(
                {x: np.full((1,), y) for x, y in packet_data.items() if x not in self.input_layer.exclude_features}
            )

            if self.counter.get_packet_count_preprocessed() > 1:

                input = self.packet_queue[0]
                results = self.model.predict(input)
                print(results)
