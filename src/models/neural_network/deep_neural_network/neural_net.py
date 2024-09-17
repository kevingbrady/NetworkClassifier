import os
import tensorflow as tf
from keras.models import Sequential
from keras.layers import BatchNormalization, Dense, Dropout, InputLayer
from src.models.neural_network.input_layer import CustomInputLayer
from docker_info import DOCKER_PREFIX


class NeuralNet:

    name = "DeepNeuralNet"
    model_filepath = DOCKER_PREFIX  + 'src/models/neural_network/deep_neural_network/DeepNeuralNet'
    optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
    loss = tf.keras.losses.BinaryCrossentropy()
    metrics = ['accuracy', 'Precision', 'Recall']  # 'AUC']
    jit_compile = True
    input_layer = CustomInputLayer()
    epochs = 20

    def __init__(self, manager):

        if not os.path.exists(self.model_filepath):
            os.mkdir(self.model_filepath)

        self.input_tensor = self.input_layer(manager)

        self.classifier = Sequential([
            BatchNormalization(),
            Dense(self.input_layer.num_features, activation='relu', kernel_initializer='he_uniform'),
            BatchNormalization(),
            Dropout(0.2),
            Dense(self.input_layer.num_features * 2, activation='relu', kernel_initializer='he_uniform'),
            BatchNormalization(),
            Dropout(0.4),
            Dense(self.input_layer.num_features, activation='relu', kernel_initializer='he_uniform'),
            BatchNormalization(),
            Dropout(0.2),
            Dense(1, activation='sigmoid')  # Output
        ], name='Network')(self.input_tensor)

    def save_model_diagram(self, model):
        tf.keras.utils.plot_model(
            model.get_layer('Network'),
            to_file=DOCKER_PREFIX + 'src/models/neural_network/deep_neural_network/' + self.name + '.png',  # saving
            show_layer_activations=True,
            show_shapes=True,
            show_layer_names=True,  # show shapes and layer name
            expand_nested=True  # will show nested block
        )

    def __call__(self):

        model = tf.keras.Model(
            name=self.name,
            inputs=self.input_layer.inputs,
            outputs=self.classifier
        )

        model.compile(
            optimizer=self.optimizer,
            loss=self.loss,
            metrics=self.metrics,
            jit_compile=self.jit_compile
        )

        return model