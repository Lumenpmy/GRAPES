
import argparse
from logging import basicConfig, exception, debug, error, info, warning, getLogger
import os
import pickle
import random
import re
import sys
import json
import traceback
from pathlib import Path
from datetime import date
import subprocess

from tqdm import tqdm

from rich.logging import RichHandler
from rich.progress import Progress, TaskID, track
from rich.traceback import install

# import CuckooAPI
# import extract_features
import lief

def import_added_extractor(adversarial_vector: list,bytez):
    def imports_to_dict(adversarial_imports_set: list):

        adversarial_imports_dict = {}
        for imports in adversarial_imports_set:
            if len(imports.split(":")) > 2:
                adversarial_imports_set.remove(imports)
                continue

            function_name, library = imports.split(":")
            if library not in adversarial_imports_dict:
                adversarial_imports_dict[library] = [function_name]
            else:
                functions = adversarial_imports_dict[library]
                functions.append(function_name)

        return adversarial_imports_dict, adversarial_imports_set


    feature_vector_mapping = Path("MalGAN/extract_features/feature_vector_directory/feature_import_vector_mapping.pk")
    feature_vector_mapping = pickle.load(open(feature_vector_mapping, "rb"))
    feature_vector_mapping = [import_lib for import_lib in feature_vector_mapping]
    adversarial_import = []

    print("------Generating sections set from adversarially generated feature vectors of imports!------")
    '''track(..., description="Mapping sections ...", transient=True): 
                   在这里，track 函数来自于 tqdm 库，它提供了一个进度条工具，用于显示循环的进度。track 函数的参数有：
                   range(len(adversarial_feature_vector))：这是要迭代遍历的范围，即 adversarial_feature_vector 列表的长度。
                   description="Mapping sections ..."：这是显示在进度条中的描述文本，通常用于描述正在进行的操作或处理。
                   transient=True：这个参数指定进度条是否会在迭代结束后消失，即是否为瞬时的。如果设置为 True，则进度条会在迭代完成后自动消失。'''

    for i in track(
        range(len(adversarial_vector)), description=" Extracting ... ", transient=True
    ):
        sample = adversarial_vector[i]

        if sample != 0:
           adversarial_import.append(feature_vector_mapping[i])

        # for imports in unfiltered_adversial_imports:
        #     if "32" in imports:
        #         adversial_imports.append(imports)
        #         debug("\t[+] Filtered Imports : " + str(imports))

    # print(adversarial_import)
    binary = lief.parse(bytez)

    imports = [e.name + ":" + lib.name.lower()for lib in binary.imports for e in lib.entries]
    # 统计每个对抗性样本中的导入表不在全部的恶意软件样本里的导入表的名称
    imports_to_be_added = list(set(adversarial_import).difference(set(imports)))
    adversarial_imports_dict, imports_to_be_added = imports_to_dict(imports_to_be_added)
    # print(adversarial_imports_dict)
    return adversarial_imports_dict


def section_added_extractor(adversarial_vector: list,bytez):
    feature_vector_mapping = Path("MalGAN/extract_features/feature_vector_directory/feature_section_vector_mapping.pk")
    feature_vector_mapping = pickle.load(open(feature_vector_mapping, "rb"))
    feature_vector_mapping = [section for section in feature_vector_mapping]
    adversarial_section = []
    print("------Generating sections set from adversarially generated feature vectors of sections!------")

    for i in track(
        range(len(adversarial_vector)), description="  Extracting : ", transient=True
    ):
        sample = adversarial_vector[i]#选取每一个对抗性样本的特征向量

        if sample.item() != 0:
            adversarial_section.append(feature_vector_mapping[i])

    # print(adversarial_section)
    binary = lief.parse(bytez)
    sections = [section.name for section in binary.sections]
    sections_to_be_added = list(set(adversarial_section).difference(set(sections)))
    # print(sections_to_be_added)

    return sections_to_be_added


