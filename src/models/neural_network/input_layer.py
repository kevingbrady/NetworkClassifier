import tensorflow as tf


class CustomInputLayer:

    inputs = {}
    feature_columns = []
    num_features = 0
    jit_compile = False
    exclude_features = ['No', 'Target', 'timestamp', 'src_ip', 'dst_ip']

    def __call__(self, manager):

        features = manager.features['normalized']
        self.jit_compile = manager.jit_compile

        for name in features:
            if name not in self.exclude_features:
                self.num_features += 1
                self.feature_columns.append(tf.feature_column.numeric_column(name))
                self.inputs[name] = tf.keras.layers.Input(shape=(1, ), name=name)

        return tf.keras.layers.DenseFeatures(feature_columns=self.feature_columns, name='Input')(self.inputs)
