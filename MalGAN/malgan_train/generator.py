# -*- coding: utf-8 -*-
r"""
    malgan_train.generator
    ~~~~~~~~~~~~~

    Generator block for MalGAN.

    Based on the paper: "Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN"
    By Weiwei Hu and Ying Tan.

    :version: 0.1.0
    :copyright: (c) 2019 by Zayd Hammoudeh.
    :license: MIT, see LICENSE for more details.
"""
from typing import List, Tuple

import torch
from torch import Tensor
import torch.nn as nn

TensorTuple = Tuple[Tensor, Tensor]



class Generator(nn.Module):
    r""" MalGAN generator block """

    # noinspection PyPep8Naming
    def __init__(self, M: int, Z: int, hidden_size: List[int], g: nn.Module):
        r"""Generator Constructor

        :param M: Dimension of the feature vector \p m
        :param Z: Dimension of the noise vector \p z
        :param hidden_size: Width of the hidden layer(s)，每个隐藏层的宽度列表，比方说[H1,H2,H3]
        :param g: Activation function,激活函数
        """
        super().__init__()

        self._Z = Z

        # Build the feed forward net
        self._layers, dim = nn.Sequential(), [M + self._Z] + hidden_size
        # dim是一个合并的列表，[M + self._Z,H1,H2,H3],表示每一层的输入和输出的大小，
        # 比方说第一层的输入大小为M + self._Z，输出大小为H1
        # 比方说第二层的输入大小为H1，输出大小为H2
        for i, (d_in, d_out) in enumerate(zip(dim[:-1], dim[1:])):# 利用切片操作，选择每一层的输入和输出的大小
            self._layers.add_module("FF%02d" % i, nn.Sequential(nn.Linear(d_in, d_out), g))

        # Last layer is always sigmoid
        layer = nn.Sequential(nn.Linear(dim[-1], M), nn.Sigmoid())
        self._layers.add_module("FF%02d" % len(dim), layer)

    # noinspection PyUnresolvedReferences
    def forward(self, m: torch.Tensor,
                z: torch.Tensor = None) -> TensorTuple:  # pylint: disable=arguments-differ
        r"""
        Forward pass through the generator.  Automatically generates the noise vector \p z that
        is coupled with \p m.

        :param m: Input vector :math:`m`
        :param z: Noise vector :math:`z`.  If no random vector is specified, the random vector is
                  generated within this function call via a call to \p torch.rand
        :return: Tuple of (:math:`m'`, :math:`G_{\theta_{g}}`), i.e., the output tensor with the
                 feature predictions as well as the smoothed prediction that can be used for
                 back-propagation.
        """
        '''带有dataloader'''
        if z is None:
            # num_ele = m.shape[0]
            # z = torch.rand((num_ele, self._Z))#如果没有给出噪声向量，那就随机化成和输入的样本m的个数相等的向量
            z = torch.rand(self._Z)
        # 拼接向量 m 和 z
        #o = torch.cat((m, z), dim=1)
        o = torch.cat((m, z))

        o = self._layers.forward(o)
        g_theta = torch.max(m, o)  # Ensure binary bits only set positive

        m_prime = (g_theta > 0.5).float()# 进行二值化转换
        return m_prime, g_theta
