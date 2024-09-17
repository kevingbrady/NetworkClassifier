import os
import tensorflow_decision_forests as tfdf
import src.metadata.boosted_tree_features as boosted_tree_features
from src.models.decision_tree.boosted_tree.hyperparameter_tuner import HyperparameterTuner
from docker_info import DOCKER_PREFIX


class BoostedTrees:

    name = "BoostedTreesModel"
    model_filepath = DOCKER_PREFIX + 'src/models/decision_tree/boosted_tree/BoostedTreesModel'
    task = tfdf.keras.Task.CLASSIFICATION
    num_trees = 20
    features = boosted_tree_features.features
    feature_names = []
    l2_regularization = 0.4
    num_threads = os.cpu_count()
    metrics = ['accuracy', 'Precision', 'Recall']
    epochs = 1

    #tuner = HyperparameterTuner().tuner

    def __init__(self, manager):
        
        if not os.path.exists(self.model_filepath):
            os.mkdir(self.model_filepath)

        self.feature_names = manager.feature_names

    def save_model_diagram(self, model):

        with open(DOCKER_PREFIX + 'src/models/decision_tree/boosted_tree/' + self.name + '.html', 'w+') as f:
            f.write(tfdf.model_plotter.plot_model(
                                model,
                                max_depth=self.num_trees
                        )
            )

    def __call__(self):
        model = tfdf.keras.GradientBoostedTreesModel(
            name=self.name,
            task=self.task,
            #num_trees=self.num_trees,
            features=self.features,
            #tuner=self.tuner,
            num_threads=self.num_threads,
            exclude_non_specified_features=True,
            check_dataset=False
        )

        model.compile(
            metrics=self.metrics
        )

        return model
