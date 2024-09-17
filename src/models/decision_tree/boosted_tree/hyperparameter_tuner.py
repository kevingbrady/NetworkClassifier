import os
import tensorflow_decision_forests as tfdf


class HyperparameterTuner:

    tuner = tfdf.tuner.RandomSearch(num_trials=50, trial_num_threads=os.cpu_count())

    def __init__(self):

        self.tuner.choice("categorical_algorithm", ["CART", "RANDOM"])
        self.tuner.choice("use_hessian_gain", [True, False])
        self.tuner.choice("shrinkage", [0.02, 0.05, 0.10, 0.15])
        self.tuner.choice("num_candidate_attributes_ratio", [0.2, 0.5, 0.9, 1.0])
        self.tuner.choice("split_axis", ["AXIS_ALIGNED"])
        self.tuner.choice("growing_strategy", ["BEST_FIRST_GLOBAL"])
        self.tuner.choice("max_num_nodes", [16, 32, 64, 128, 256])

    def get_tuning_logs(self, model):
        tuning_logs = model.make_inspector().tuning_logs()
        print(tuning_logs.head())
        print(tuning_logs[tuning_logs.best].iloc[0])