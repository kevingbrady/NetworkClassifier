import tensorflow as tf
from src.metadata.data_columns import columns
import keras


class InputLayer:

    inputs = []
    num_features = 0
    exclude_features = ['key', 'src_ip', 'dst_ip', 'Target']

    def get_input_tensor(self):

        return keras.layers.Concatenate()(self.inputs)

    def __init__(self):

        self.features = {x: y for x, y in columns.items() if x not in self.exclude_features}
        self.num_features = len(self.features)

        for key, value in self.features.items():
            self.inputs.append(keras.layers.Input(shape=(1,), name=key, dtype=value))
