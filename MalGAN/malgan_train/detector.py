# -*- coding: utf-8 -*-
r"""
    malgan_train.detector
    ~~~~~~~~~~~~

    Black box malware detector.

    Based on the paper: "Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN"
    By Weiwei Hu and Ying Tan.

    :version: 0.1.0
    :copyright: (c) 2019 by Zayd Hammoudeh.
    :license: MIT, see LICENSE for more details.
"""
from enum import Enum
from typing import Union

import numpy as np
import sklearn
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC

import torch
from torch import Tensor

TorchOrNumpy = Union[np.ndarray, Tensor]
from . import malconv


# noinspection PyPep8Naming
class BlackBoxDetector:
    r"""
    Black box detector that intends to mimic an antivirus/anti-Malware program that detects whether
    a specific program is either malware or benign.
    """
    class Type(Enum):
        r""" Learner algorithm to be used by the black-box detector """
        DecisionTree = DecisionTreeClassifier()
        LogisticRegression = LogisticRegression(solver='lbfgs', max_iter=int(1e6))
        MultiLayerPerceptron = MLPClassifier()
        RandomForest = RandomForestClassifier(n_estimators=100)
        SVM = SVC(gamma="auto")
        MalConv=malconv.MalConv()

        @classmethod
        def names(cls):
            r""" Builds the list of all enum names """
            return [c.name for c in cls]

        @classmethod
        def get_from_name(cls, name):
            r"""
            Gets the enum item from the specified name

            :param name: Name of the enum object
            :return: Enum item associated with the specified name
            """
            for c in BlackBoxDetector.Type:
                if c.name == name:
                    return c
            raise ValueError("Unknown enum \"%s\" for class \"%s\"", name, cls.name)


    def __init__(self, learner_type: 'BlackBoxDetector.Type'):
        self.type = learner_type
        if learner_type == BlackBoxDetector.Type.MalConv:
            self._model = self.type.value
        else:
            self._model = sklearn.clone(self.type.value)
        self.training = True


    def fit(self, X: TorchOrNumpy, y: TorchOrNumpy):

        r"""
        Fits the learner.  Supports NumPy and PyTorch arrays as input.  Returns a torch tensor
        as output.

        :param X: Examples upon which to train
        :param y: Labels for the examples
        """
        if isinstance(X, Tensor):
            X = X.numpy()
        if isinstance(y, Tensor):
            y = y.numpy()
        if self.type != BlackBoxDetector.Type.MalConv:
            self._model.fit(X, y)
        self.training = False


    def predict(self, X: TorchOrNumpy) -> Tensor:


        r"""
        Predict the labels for \p X

        :param X: Set of examples for which label probabilities should be predicted
        :return: Predicted value for \p X
        """
        if self.training:
            raise ValueError("Detector is not trained yet but trying to predict.")
        if isinstance(X, Tensor):
            X = X.numpy()
        if self.type == BlackBoxDetector.Type.MalConv:
            y = self._model.predict_features_label(X)
        else:
            y = self._model.predict(X)
        # return torch.from_numpy(np.array([y])).float()
        return torch.from_numpy(np.array(y))


