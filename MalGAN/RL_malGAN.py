import logging
from enum import Enum
from typing import List, Tuple, Union
from pathlib import Path
from torch import Tensor
import torch.nn as nn
import torch.utils.data
from MalGAN.malgan_train.discriminator import Discriminator
from MalGAN.malgan_train.generator import Generator

ListOrInt = Union[List[int], int]
PathOrStr = Union[str, Path]
TensorTuple = Tuple[Tensor, Tensor]


IS_CUDA = torch.cuda.is_available()
if IS_CUDA:
    device = torch.device('cuda:0')
    torch.set_default_tensor_type(torch.cuda.FloatTensor)

class MalGAN(nn.Module):
    def __init__(self,M:int,Z: int,h_gen: ListOrInt, h_discrim: ListOrInt,g_hidden: nn.Module = nn.LeakyReLU):
        r"""
        Malware Generative Adversarial Network Constructor

        :param M: Dimension of the input file
        :param Z: Dimension of the noise vector \p z
        :param test_split: Fraction of input data to be used for testing
        :param h_gen: Width of the hidden layer(s) in the GENERATOR.  If only a single hidden
                      layer is desired, then this can be only an integer.
        :param h_discrim: Width of the hidden layer(s) in the DISCRIMINATOR.  If only a single
                          hidden layer is desired, then this can be only an integer.
        """
        super().__init__()

        if Z <= 0:
            raise ValueError("Z must be a positive integers")
        self.M, self.Z = M, Z  # pylint: disable=invalid-name
        if isinstance(h_gen, int):
            h_gen = [h_gen]
        if isinstance(h_discrim, int):
            h_discrim = [h_discrim]
        self.d_discrim, self.d_gen = h_discrim, h_gen
        for h_size in [self.d_discrim, self.d_gen]:
            for w in h_size:
                if w <= 0:
                    raise ValueError("All hidden layer widths must be positive integers.")

        if not isinstance(g_hidden, nn.Module):
            g_hidden = g_hidden()
        self._g = g_hidden

        self._is_cuda = IS_CUDA
        self._gen = Generator(M=self.M, Z=self.Z, hidden_size=h_gen, g=self._g)
        self._discrim = Discriminator(M=self.M, hidden_size=h_discrim, g=self._g)



def test_malGAN(feature_vector,features_type):


    # 初始化 MalGAN 模型
    malgan = MalGAN(M=len(feature_vector), Z=10, h_gen=[256, 512, 256], h_discrim=[256, 512, 256])
    if features_type == 'section':
        malgan.load_state_dict(torch.load('MalGAN/saved_models/malgan_section_train_z=10_d-gen=[256,_512,_256]_d-disc=[256,_512,_256]_bs=50_bb=malconv_g=relu_final.pth'))
        print('------malGAN-Obtain adversarial feature vectors of the sections of the PE file!------')
    if features_type == 'import':
        malgan.load_state_dict(torch.load('MalGAN/saved_models/malgan_train_import_z=10_d-gen=[256,_512,_256]_d-disc=[256,_512,_256]_bs=50_bb=malconv_g=relu_final.pth'))
        print('------malGAN-Obtain adversarial feature vectors of the imports of the PE file!------')
    # 使用生成器生成数据
    with torch.no_grad():
        adversrial_feature = malgan._gen(feature_vector)[0]
        # print(adversrial_feature)
        prediction = malgan._discrim(adversrial_feature)
        print(f"malGAN-Discriminator Prediction (probability of being malware) of the adversarial feature vectors : {prediction.item()}")
    return adversrial_feature



