import argparse
import glob
import pickle
from logging import info, warning
import re
from pathlib import Path
from random import shuffle

from datetime import date

from pyfiglet import Figlet

from sklearn.model_selection import train_test_split

import lief
import torch
from torch.utils.data import DataLoader, Dataset

# Installing rich modules for pretty printing
from rich.logging import RichHandler
from rich.progress import track
from rich.traceback import install
from rich import print
from rich.panel import Panel
from rich.text import Text
from rich.table import Table




def features_mapping_import_index(bytez):
    def filter_imported_functions(func_string_with_library):
        func_string = func_string_with_library.split(":")[0]

        if re.match("^[a-zA-Z]*$", func_string):
            return True
        else:
            return False

    feature_vector_mapping= Path("MalGAN/extract_features/feature_vector_directory/feature_import_vector_mapping.pk")
    feature_vector_mapping = pickle.load(open(feature_vector_mapping, "rb"))
    feature_vector_mapping = [import_lib for import_lib in feature_vector_mapping]
    print('------Start extracting feature vectors for imports about PE malware files!------ ')
    binary = lief.parse(bytez)

    if str(binary.optional_header.magic) != "PE_TYPE.PE32":  # 判断是否是32位PE文件
        warning(f"\t[-] {bytez} is not a 32 bit application ...")
        print('ERROR!This PE file is not 32-bit!')

    imports = [e.name + ':' + lib.name.lower() for lib in binary.imports for e in lib.entries]
    imports = list(filter(lambda x: filter_imported_functions(x), imports))
    feature_vector = [0] * len(feature_vector_mapping)

    for import_function in imports:
        if import_function in feature_vector_mapping:
            index = feature_vector_mapping.index(import_function)
            feature_vector[index] = 1

    return torch.tensor(feature_vector)

def features_mapping_section_index(bytez):
    feature_vector_mapping = Path("MalGAN/extract_features/feature_vector_directory/feature_section_vector_mapping.pk")
    feature_vector_mapping = pickle.load(open(feature_vector_mapping, "rb"))
    feature_vector_mapping = [import_lib for import_lib in feature_vector_mapping]
    # print(feature_vector_mapping)
    print('------Start extracting feature vectors for sections about PE malware files!------ ')
    binary = lief.parse(bytez)
    if str(binary.optional_header.magic) != "PE_TYPE.PE32":
        warning("\t[-] {file} is not a 32 bit application ...")
        print('ERROR!This PE file is not 32-bit!')
    sections = [section.name for section in binary.sections]

    feature_vector = [0] * len(feature_vector_mapping)
    for section in sections:
        if section in feature_vector_mapping:
            index = feature_vector_mapping.index(section)
            feature_vector[index] = 1
    return torch.tensor(feature_vector)


