import keras
from src.metadata.data_columns import columns, columns_normalized


class InputLayer:

    inputs = {}
    features = {}
    num_features = 0
    jit_compile = False
    exclude_features = [
        'No',
        'Target',
        'timestamp',
        'src_ip',
        'dst_ip',
        #'fwd_seg_size_avg',
        #'bwd_seg_size_avg',
        #'cwe_flag_count',
        #'subflow_fwd_pkts',
        #'subflow_bwd_pkts',
        #'subflow_fwd_byts',
        #'subflow_bwd_byts'
    ]

    def __init__(self):

        self.features = {x: y for x, y in columns.items() if x not in self.exclude_features}

        self.num_features = len(self.features)

        for key, value in self.features.items():
            self.inputs[key] = keras.layers.Input(shape=(1, ), name=key,  dtype=value)
