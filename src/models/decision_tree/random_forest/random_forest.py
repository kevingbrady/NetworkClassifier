import os
import tensorflow_decision_forests as tfdf
import src.metadata.boosted_tree_features as boosted_tree_features
import pandas as pd
from docker_info import DOCKER_PREFIX

class RandomForest:

    name = "RandomForestModel"
    model_filepath = DOCKER_PREFIX + 'src/models/decision_tree/random_forest/RandomForestModel'
    task = tfdf.keras.Task.CLASSIFICATION
    features = boosted_tree_features.features
    feature_names = []
    num_threads = os.cpu_count()
    num_trees = 50
    metrics = ['accuracy', 'Precision', 'Recall']
    epochs = 1

    #tuner = tfdf.tuner.RandomSearch(num_trials=20, trial_num_threads=num_threads)

    def __init__(self, manager):

        if not os.path.exists(self.model_filepath):
            os.mkdir(self.model_filepath)

        self.feature_names = manager.feature_names

    def save_model_diagram(self, model):

        with open(DOCKER_PREFIX + 'src/models/decision_tree/random_forest/' + self.name + '.html', 'w+') as f:
            f.write(tfdf.model_plotter.plot_model(
                model,
                max_depth=self.num_trees
            )
            )

    def __call__(self):
        model = tfdf.keras.RandomForestModel(
            name=self.name,
            task=self.task,
            features=self.features,
            #tuner=self.tuner,
            num_threads=self.num_threads,
            num_trees=self.num_trees,
            exclude_non_specified_features=True,
            check_dataset=False
        )

        model.compile(
            metrics=self.metrics
        )

        return model
