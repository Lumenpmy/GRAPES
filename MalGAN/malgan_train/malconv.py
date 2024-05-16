#!/usr/bin/python
"""
Defines the MalConv architecture.
Adapted from https://arxiv.org/pdf/1710.09435.pdf
Things different about our implementation and that of the original paper:
 * The paper uses batch_size = 256 and
   SGD(lr=0.01, momentum=0.9, decay=UNDISCLOSED, nesterov=True )
 * The paper didn't have a special EOF symbol
 * The paper allowed for up to 2MB malware sizes,
   we use 1.0MB because of memory on a Titan X
 """
import os
import sys
import torch

import numpy as np
import tensorflow as tf
from keras import metrics
from keras.models import load_model
from keras.optimizers import SGD


module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
# 给出所在文件的所在目录
model_path = os.path.join(module_path, "malconv.h5")
# 打开与训练好的MalConv模型

tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)


class MalConv:
    def __init__(self):
        self.batch_size = 100
        self.input_dim = 257  # every byte plus a special padding symbol
        self.padding_char = 256
        self.malicious_threshold = 0.5

        self.model = load_model(model_path)
        _, self.maxlen, self.embedding_size = self.model.layers[1].output_shape

        self.model.compile(
            loss="binary_crossentropy",
            optimizer=SGD(lr=0.01, momentum=0.9, nesterov=True, decay=1e-3),
            metrics=[metrics.binary_accuracy],
        )

    def extract(self, bytez):
        b = np.ones((self.maxlen,), dtype=np.int16) * self.padding_char
        bytez = np.frombuffer(bytez[: self.maxlen], dtype=np.uint8)
        b[: len(bytez)] = bytez
        print(type(b))
        print(b.shape)
        return b


    def predict_sample(self, bytez):
        return self.model.predict(bytez.reshape(1, -1))[0][0]

    def adjust_features(self, features):
        '''处理dataloader'''
        adjusted_features = []
        for feature in features:
            if len(feature) < self.maxlen:
                # 进行填充
                padding_length = self.maxlen - len(feature)
                padded_feature = np.pad(feature, (0, padding_length), 'constant', constant_values=(self.padding_char,))
                adjusted_features.append(padded_feature)
            elif len(feature) > self.maxlen:
                adjusted_features.append(feature[:self.maxlen])
            else:
                adjusted_features.append(feature)
        '''处理单个特征向量'''
        # if len(features) < self.maxlen:
        #     # 进行填充
        #     padding_length = self.maxlen - len(features)
        #     adjusted_features = np.pad(features, (0, padding_length), 'constant', constant_values=(self.padding_char,))
        # elif len(features) > self.maxlen:
        #     adjusted_features=features[:self.maxlen]
        # else:
        #     adjusted_features=features
        # # print(adjusted_features.shape)
        # print(np.array(adjusted_features))
        return np.array(adjusted_features)

    def predict_features_proba(self, features):
        if isinstance(features, torch.Tensor):
            features = features.numpy()  # 如果是 PyTorch Tensor，转换为 NumPy 数组
        adjusted_features = self.adjust_features(features)
        prediction = []
        for feature in adjusted_features:
            if len(feature.shape) == 1:
                expand_features = np.expand_dims(feature, axis=0)
                prediction.append(self.model.predict(expand_features)[0][0])
        return torch.from_numpy(np.array(prediction))

    def predict_features_label(self, features):
        # 确保 features 是 NumPy 数组
        if isinstance(features, torch.Tensor):
            features = features.numpy()  # 如果是 PyTorch Tensor，转换为 NumPy 数组
        adjusted_features = self.adjust_features(features)
        prediction = []
        for feature in adjusted_features:
            if len(feature.shape) == 1:
                expand_features = np.expand_dims(feature, axis=0)
                prediction.append(self.model.predict(expand_features)[0][0])
        # 将列表转换为数组
        predictions = np.array(prediction)
        # 使用阈值生成标签数组
        labels = (predictions > self.malicious_threshold).astype(int)
        return labels

    def fetch_file(self,sample_path):
        with open(sample_path, "rb") as f:
            bytez = f.read()
        return bytez









