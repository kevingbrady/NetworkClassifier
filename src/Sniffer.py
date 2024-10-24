from __future__ import print_function
import logging, os

logging.disable(logging.WARNING)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import keras
import ydf
import tensorflow_decision_forests as tfdf
import psutil
import numpy as np
import json
from scapy.all import *

conf.sniff_promisc = False

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.PacketDataNormalizer import PacketDataNormalizer
from src.metadata.input_layer import InputLayer
from src.utils import pretty_time_delta, normalize

#MODEL_FILEPATH = 'src/models/neural_network/deep_neural_network/DeepNeuralNet'
#MODEL_FILEPATH = 'src/models/neural_network/logistic_regression/LogisticRegression'
#MODEL_FILEPATH = 'src/models/decision_tree/random_forest/RandomForestModel'
MODEL_FILEPATH = 'src/models/decision_tree/boosted_tree/BoostedTreesModel'


class Sniffer:
    counter = PacketCounter()
    flow_meter = FlowMeterMetrics(output_mode="flow")
    normalizer = PacketDataNormalizer()
    start_time = 0.0

    def __init__(self, interfaces=None):

        self.model = self.load_model(MODEL_FILEPATH)
        self.input_layer = InputLayer()
        self.ifaces = []
        self.predictions = {}
        self.display_flow_count = 0
        self.display_output = ''

        if interfaces is None:
            iface_dict = psutil.net_if_stats()
            for key, value in iface_dict.items():
                if (key != 'lo') and (value.isup is True):
                    self.ifaces.append(key)

        else:
            self.ifaces = interfaces

    def load_model(self, model_filepath):

        model = None

        if 'decision_tree' in model_filepath:
            model = ydf.from_tensorflow_decision_forests(model_filepath)

        elif 'neural_network' in model_filepath:
            model = keras.models.load_model(model_filepath + '.keras')

        return model

    def run(self):

        sniffer = AsyncSniffer(iface=self.ifaces, prn=self.process_packet, store=False)
        try:
            sniffer.start()
            sniffer.join()

        except KeyboardInterrupt:
            elapsed_time = time.time() - self.start_time
            sniffer.stop()
            print(
                "\nSniffed %d packets in %s" % (self.counter.get_packet_count_total(), pretty_time_delta(elapsed_time)))
            raise KeyboardInterrupt

    def process_packet(self, pkt):

        if self.counter.get_packet_count_total() == 0:
            self.start_time = pkt.time

        self.counter.packet_count_total += 1

        if ('IP' in pkt) or ('IPv6' in pkt):

            if ('TCP' in pkt) or ('UDP' in pkt):

                self.counter.packet_count_preprocessed += 1

                flow, direction = self.flow_meter.process_packet(pkt)
                packet_data = flow.get_data(direction)

                params = {}

                if flow.packet_count.get_total() >= 3:

                    flow_input = {x: np.full((1,), y) for x, y in flow.get_data().items() if
                                  x not in self.input_layer.exclude_features}
                    #print(flow_input)
                    if self.model.name in ("DeepNeuralNet", "LogisticRegression"):
                        params = {
                            'verbose': 0
                        }

                    flow.prediction = self.model.predict(flow_input, **params)

                update = ''.join([flow.get_short_flow_output() for key, flow in self.flow_meter.flows.items() if flow.packet_count.get_total() >= 3])

                if self.display_output != update:
                    magic_char = '\033[F'
                    os.system('cls||clear')
                    self.display_output = ''.join([flow.get_short_flow_output() for key, flow in self.flow_meter.flows.items() if flow.packet_count.get_total() >= 3])
                    self.display_flow_count = self.display_output.count('\n')
                    ret_depth = magic_char * self.display_flow_count

                    print('{}{}'.format(ret_depth, self.display_output), flush=True, end='')
                    print(self.display_flow_count, "flows recorded ...")
