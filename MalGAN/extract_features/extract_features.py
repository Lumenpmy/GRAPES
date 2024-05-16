import argparse
import glob
from logging import basicConfig, exception, debug, error, info, warning, getLogger
import os
import pickle
import re
import sys
import time
import traceback
# from handlers import TimedRotatingFileHandler
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

install()

SECTION_INDEX = 0


def parse_args():
    parser = argparse.ArgumentParser(
        description='PE File Feature Extraction. \nThe purpose of this application is extract the feature vectors from PE files for the purpose of malware analysis and malware mutation.')

    parser.add_argument('-m', "--malware-path",
                        help="The filepath of the malicious PE files whose features are to be extracted.", type=Path,
                        default=Path("Data/malware"))
    parser.add_argument('-b', "--benign-path",
                        help="The filepath of the benign PE files whose features are to be extracted.", type=Path,
                        default=Path("Data/benign"))
    parser.add_argument('-o', "--output-dir",
                        help="The filepath to where the feature vectors will be extracted. If this location does not exist, it will be created.",
                        type=Path, default=Path("feature_vector_directory"))
    parser.add_argument('-f', "--logfile", help="The file path to store the logs.", type=Path,
                        default=Path("extract_features_logs_" + str(date.today()) + ".log"))

    logging_level = ["debug", "info", "warning", "error", "critical"]
    parser.add_argument(
        "-l",
        "--log",
        dest="log",
        metavar="LOGGING_LEVEL",
        choices=logging_level,
        default="info",
        help=f"Select the logging level. Keep in mind increasing verbosity might affect performance. Available choices include : {logging_level}",
    )

    args = parser.parse_args()  # 解析通过命令行传递的参数赋给args
    return args


def logging_setup(logfile: str, log_level: str):
    log_dir = "Logs"

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    logfile = os.path.join(log_dir, logfile)

    basicConfig(
        level=log_level.upper(),
        filemode='a',  # other options are w for write.
        format="%(message)s",
        filename=logfile
    )

    getLogger().addHandler(RichHandler())


'''
所以整个features_mapping_index（）目的：（相当于安德森版本2的从PE文件中提取特征的文件，因为第一个版本没有在提取特征的时候实现）
1.文件列表
output_path
    malware
        malware_feature_set.pk  # 恶意软件样本在feature_vector_mapping.pk中所有特征的具有情况（0、1表示）
    benign
        benign_feature_set.pk  # 良性软件样本在feature_vector_mapping.pk中所有特征的具有情况（0、1表示）
    feature_vector_mapping.pk# 统计的所有的32位的良性和恶行样本所具有的不重复的导入表对（只有大小写组成的函数入口名：所属的库名）和字节名
    '''


def features_mapping_index(malware_path: str, benign_path: str, output_path: str):
    malware_feature_vector_directory, benign_feature_vector_directory = setup_directories(malware_path, benign_path,
                                                                                          output_path)

    malware_pe_files = [os.path.join(malware_path, files) for files in os.listdir(malware_path)]  # 得到每个恶意软件样本的路径
    # os.listdir()用于访问malware_path下的所有文件，返回这些文件组成的列表
    benign_pe_files = [os.path.join(benign_path, files) for files in os.listdir(benign_path)]

    # Reading Imports filter files
    debug("[*] Reading filtered Imports file ...")
    filtered_imports_file = Path("manipulation_content/imports_content.txt")
    with open(str(filtered_imports_file), 'r') as file:
        filtered_imports = file.read()

    filtered_imports_file = filtered_imports.split('\n')

    debug(f"Number of malware files : {(len(malware_pe_files))}")
    debug(f"Number of benign files : {(len(benign_pe_files))}")
    debug(f"Number of total files : {(len(malware_pe_files) + len(benign_pe_files))}")
    debug(f"Output directory : {str(output_path)}")
    # 恶意和良性样本存储在output_path下的malware和benign下

    # 统计所有32位PE文件不重复引用的：（由大小写字母组成的）函数入口名：所属的库名的信息（feature_vector_mapping）
    info("[*] Creating import features mapping ... \n")

    # feature_vector_mapping = {}
    import_feature_vector_mapping = {}
    section_feature_vector_mapping = {}

    # index = 0
    error_files = []
    index_section = 0
    index_import = 0

    files = malware_pe_files + benign_pe_files

    info("\t[*] Starting import extraction ...")
    # for i, file in enumerate(malware_pe_files + benign_pe_files):
    for i in track(range(len(files)), description="Extracting imports ... ", transient=True):
        file = files[i]
        debug(f'\t[+] Num: {i} - Name: {file} - Number of import features: {len(import_feature_vector_mapping)}')
        # input("begining of the loop")
        a = 0
        try:
            a = 1
        except:
            a = 3
        try:
            win32, feature_vector_mapping, index_import = extract_imports(file, import_feature_vector_mapping,
                                                                          filtered_imports_file, index_import)
            # win32, import_feature_vector_mapping, index_import = extract_imports(file, import_feature_vector_mapping, filtered_imports_file, index_import)

            if not win32:
                exception(f"\t[*] Deleting PE file : [bold red]{file}", extra={"markup": True})
                os.remove(file)
                # files.remove(file)
                error_files.append(file)
                exception(f"\t[-] {file} has been deleted ...")  # 删除不是32位的PE文件

            pass
        except:
            traceback.print_exc()

            exception(f"\t[*] Deleting PE file : [bold red]{file}", extra={"markup": True})
            os.remove(file)
            # files.remove(file)
            error_files.append(file)
            exception(f"\t[-] {file} has been deleted ...")

        # debug(f"\t[+] Index Import : {index_import}")

    SECTION_INDEX = index_import  # 节名开始的序列值

    info(f"\t[+] Import extraction completed with {SECTION_INDEX} imports... \n")

    # 开始统计所有的32位PE文件所使用的节名字
    info("\t[*] Starting section extraction ...")

    debug(f"[-] Number of files skipped and deleted: {len(error_files)}")
    # input("TEsT")

    # for i, file in enumerate(malware_pe_files + benign_pe_files):
    for i in track(range(len(files)), description="Extracting sections ...: ", transient=True):
        file = files[i]

        debug(f'\t[+] Num: {i} - Name: {file} - Number of section features: {len(section_feature_vector_mapping)}')

        # Check if the file threw an error before, and if it does, skip it.
        if file in error_files:
            warning(f"[-] This file is in the error_files list and will be skipped!")
            # input("stop here")
            continue

        # 为什么没有filter_scetions_file?不需要用section-content.txt?和import不一样？
        try:
            win32, feature_vector_mapping, index_section = extract_sections(file, section_feature_vector_mapping,
                                                                            index_section)
            # win32, section_feature_vector_mapping, index_section = extract_sections(file, section_feature_vector_mapping, index_section)

            if not win32:
                exception(f"\t[*] Deleting PE file : {file}")
                os.remove(file)
                # files.remove(file)
                error_files.append(file)
                exception(f"\t[-] {file} has been deleted ...")

            pass
        except:
            traceback.print_exc()

            exception(f"\t[*] Deleting PE file : {file}")
            os.remove(file)
            # files.remove(file)
            error_files.append(file)
            exception(f"\t[-] {file} has been deleted ...")
            pass

        # debug("\t[+] Index Section : {index_section}")

    # info(f"\t[+] Section extraction completed with {index_section} sections ... \n")
    info("[+] Features mapping to index is complete ... \n")
    # debug(f"Total size of feature vector mapping : {len(feature_vector_mapping)} \n")

    info("[*] Pickling Feature vector mapping ...")

    # for i, import_lib in enumerate(feature_vector_mapping):
    #     debug(f"\t[+] feature vector value at [{i}] : {str(import_lib)}")

    for i, import_lib in enumerate(section_feature_vector_mapping):
        debug(f"\t[+] feature vector value at [{i}] : {str(import_lib)}")

    for i, import_lib in enumerate(import_feature_vector_mapping):
        debug(f"\t[+] feature vector value at [{i}] : {str(import_lib)}")

    # pickle.dump(feature_vector_mapping,
    #             open(os.path.join(output_path,"feature_vector_mapping.pk"), 'wb'))
    # 这是pickle模块中的一个函数，用于将Python对象序列化并保存到文件中，就是output_path下的feature_vector_mapping.pk文件中
    # 也就是将feature_vector_mapping（字典特征向量，lib_import:(只包含大小写的函数入口名:所属的库名)，section:节的名字）存入
    # 长度为：现有PE文件的导入表对+节的长度，包括良性和恶意

    pickle.dump(import_feature_vector_mapping,
                open(os.path.join(output_path, "import_feature_vector_mapping.pk"), 'wb'))

    pickle.dump(section_feature_vector_mapping,
                open(os.path.join(output_path, "section_feature_vector_mapping.pk"), 'wb'))

    info(f"[+] Pickling feature vector mapping complete. You can find them at logs : [bold green]{output_path}\n",
         extra={"markup": True})
    # debug(f"\t -> Feature Vector mapping - {str(os.path.join(output_path,'feature_vector_mapping.pk'))} ", extra={"markup":True})
    debug(
        f"\t -> Import Feature Vector mapping - {str(os.path.join(output_path, 'import_feature_vector_mapping.pk'))} ",
        extra={"markup": True})
    debug(
        f"\t -> Section Feature Vector mapping - {str(os.path.join(output_path, 'section_feature_vector_mapping.pk'))} ",
        extra={"markup": True})

    # For feature vector with imports and sections:
    info("[*] Creating feature vector with imports and sections for [bold red] malware set...", extra={"markup": True})
    # 得到每个32位PE文件的关于导入表和节的特征向量（不是PE文件所有的库、函数和节，而是现在所有的PE文件中所具有的）
    # malware_pe_files_feature_set = torch.Tensor(feature_generation(malware_pe_files, feature_vector_mapping))
    # info("[*] Creating feature vector with imports and sections for [bold green] benign set...", extra={"markup":True})
    # benign_pe_files_feature_set = torch.Tensor(feature_generation(benign_pe_files, feature_vector_mapping))
    #
    # pickle.dump(malware_pe_files_feature_set, open(os.path.join(malware_feature_vector_directory, "malware_feature_set.pk"), 'wb'))
    # pickle.dump(benign_pe_files_feature_set, open(os.path.join(benign_feature_vector_directory, "benign_feature_set.pk"), 'wb'))

    # ---------------------------------#
    # For feature vector with imports: #
    # ---------------------------------#
    debug(f"[*] Creating feature vector with imports for malware set ...")
    malware_pe_files_import_feature_set = torch.Tensor(
        feature_generation(malware_pe_files, import_feature_vector_mapping))
    debug("[*] Creating feature vector with imports for benign set ...")
    benign_pe_files_import_feature_set = torch.Tensor(
        feature_generation(benign_pe_files, import_feature_vector_mapping))

    debug(f"[+] malware_pe_files_import_feature_set type : [bold green] {str(malware_pe_files_import_feature_set)}",
          extra={"markup": True})
    debug(
        f"[+] malware_pe_files_import_feature_set size : [bold green]{str(malware_pe_files_import_feature_set.shape)}")

    pickle.dump(malware_pe_files_import_feature_set,
                open(os.path.join(malware_feature_vector_directory, "malware_pe_files_import_feature_set.pk"), 'wb'))
    pickle.dump(benign_pe_files_import_feature_set,
                open(os.path.join(benign_feature_vector_directory, "benign_pe_files_import_feature_set.pk"), 'wb'))

    # ---------------------------------#
    # For feature vector with sections:#
    # ---------------------------------#
    debug("[*] Creating feature vector with sections for malware set...")
    malware_pe_files_section_feature_set = torch.Tensor(
        feature_generation(malware_pe_files, section_feature_vector_mapping))
    debug("[*] Creating feature vector with sections for benign set...")
    benign_pe_files_section_feature_set = torch.Tensor(
        feature_generation(benign_pe_files, section_feature_vector_mapping))

    debug(f"[+] malware_pe_files_section_feature_set type : {str(malware_pe_files_section_feature_set)}",
          extra={"markup": True})
    debug(f"[+] malware_pe_files_section_feature_set size : {str(malware_pe_files_section_feature_set.shape)}")

    pickle.dump(malware_pe_files_section_feature_set,
                open(os.path.join(malware_feature_vector_directory, "malware_pe_files_section_feature_set.pk"), 'wb'))
    pickle.dump(benign_pe_files_section_feature_set,
                open(os.path.join(benign_feature_vector_directory, "benign_pe_files_section_feature_set.pk"), 'wb'))

    pass


# From ALFA Adv-mlaware-viz
def filter_imported_functions(func_string_with_library):
    """
    Filters the returned imported functions of binary to remove those with special characters (lots of noise for some reason),
    and require functions to start with a capital letter since Windows API functions seem to obey Upper Camelcase convension.

    Update: The limitation for the upper case in the preprocessing step has been removed.
    """
    func_string = func_string_with_library.split(":")[0]

    if re.match("^[a-zA-Z]*$", func_string):
        return True  # 这是用正则表达式去匹配提取的imports中的函数入口名字是否只包含大小写字母
    else:
        return False


# From ALFA Adv-mlaware-viz
def remove_encoding_indicator(func_string):
    """
    In many functions there is a following "A" or "W" to indicate unicode or ANSI respectively that we want to remove.
    Make a check that we have a lower case letter
    """
    if (func_string[-1] == 'A' or func_string[-1] == 'W') and func_string[-2].islower():
        return func_string[:-1]
    else:
        return func_string


# From ALFA Adv-mlaware-viz
def process_imported_functions_output(imports):
    imports = list(filter(lambda x: filter_imported_functions(x), imports))
    # 保留下来的：函数入口名：所属库名中函数入口名都是大小写字母组成的
    # imports = list(map(lambda x: remove_encoding_indicator(x), imports))

    return imports


# 在进行哈希处理
def feature_generation(pe_files: list, feature_vector_mapping: dict):
    pe_files_feature_set = []

    # 相当于构建每个样本的feature_vector，feature_vextor包含所有的32位PE文件中引入的库以及只包含大小写的函数入口名，以及节名称，1表示含有对应的西悉尼，0表示没有
    # for i, file in enumerate(pe_files):
    for i in track(range(len(pe_files)), description="Generating feature vectors ... ", transient=True):
        file = pe_files[i]

        debug(f'\t[+] Num: {i} - Name: [bold green]{file} ', extra={"markup": True})
        feature_vector = [0] * len(feature_vector_mapping)

        try:
            binary = lief.parse(file)
            imports = [e.name + ':' + lib.name.lower() for lib in binary.imports for e in lib.entries]
            imports = process_imported_functions_output(imports)

            sections = [section.name for section in binary.sections]

            for lib_import in imports:
                if lib_import in feature_vector_mapping:
                    index = feature_vector_mapping[lib_import]
                    feature_vector[index] = 1

            for section in sections:
                if section in feature_vector_mapping:
                    index = feature_vector_mapping[section]
                    feature_vector[index] = 1

        except:
            exception(f"\t[-] {file} is not parseable!")
            raise Exception(f"\t[-] {file} is not parseable!")

        # pe_files_feature_vectors.append(feature_vector)
        # pe_files_feature_vectors.append(file)

        # debug("pe_files_feature_vectors (features, file)" + str(pe_files_feature_vectors))
        pe_files_feature_set.append(feature_vector)

    debug(f"\t[+] Vectors Type : {str(type(pe_files_feature_set))}")
    debug("[+] Feature Generation complete ... \n")

    return pe_files_feature_set


# 统计PE文件的总体的引入库、函数的情况，并不是将每个PE文件引入的库和函数进行特征提取
def extract_imports(file, feature_vector_mapping: dict, filtered_import_list: list, index: int = 0, win32: bool = True):
    binary = lief.parse(file)

    debug(f"\t[+] [bold green]{file}[/bold green] File Type : [bold red]{str(binary.optional_header.magic)}",
          extra={"markup": True})
    # 记录文件的名称和可选的头部信息

    if str(binary.optional_header.magic) != "PE_TYPE.PE32":  # 判断是否是32位PE文件
        warning(f"\t[-] {file} is not a 32 bit application ...")

        win32 = False

        return win32, feature_vector_mapping, index

    # imports includes the library (DLL) the function comes from
    imports = [e.name + ':' + lib.name.lower() for lib in binary.imports for e in lib.entries]  # RL中对于PE文件的导入表特征提取操作相同
    # 嵌套循环：得到PE文件引入的库和库中引入的函数入口，最后返回：函数入口名字：函数所属的库名的小写形式

    # preprocess imports to remove noise
    imports = process_imported_functions_output(imports)
    # 返回函数入口只有大小写的imports

    # debug("\n\t-> Imports (After): " + str(imports))

    for lib_import in imports:

        if lib_import not in feature_vector_mapping:
            if lib_import in filtered_import_list and "hal.dll" not in lib_import:
                # hal.dll”（硬件抽象层 DLL）是 Windows 操作系统中的一个标准组件，几乎所有运行 Windows 的计算机上都会有
                # debug("\t\t--> Present in filtered import list")
                debug(f"\t\t[+] Unique lib Imports added: [bold yellow]{str(lib_import)}", extra={"markup": True})
                feature_vector_mapping[lib_import] = index
                index += 1

    return win32, feature_vector_mapping, index


# win32=True表示PE文件时32位，然后feature_vector_mapping是将所有的PE文件导入的库(不包含hal.dll)和函数入口名（只有大小写字母组成的）进行集合
# index表示 feature_vector_mapping的数量

def extract_sections(file, feature_vector_mapping: dict, index: int = 0, win32: bool = True):
    # debug(file)
    binary = lief.parse(file)

    debug(f"\t[+] [bold green]{file}[/bold green] File Type : [bold red]{str(binary.optional_header.magic)}",
          extra={"markup": True})

    if str(binary.optional_header.magic) != "PE_TYPE.PE32":
        warning("\t[-] {file} is not a 32 bit application ...")

        win32 = False

        return win32, feature_vector_mapping, index

    sections = [section.name for section in binary.sections]

    for section in sections:
        if section not in feature_vector_mapping:
            feature_vector_mapping[section] = index
            debug(f"\t[+] Added {str(feature_vector_mapping[section])} at index [{index}]")
            index += 1

    return win32, feature_vector_mapping, index


def setup_directories(malware_path: str, benign_path: str, output_path: str):
    info("[*] Setting up output directories for feature vectors ...")

    feature_vector_directory = output_path
    malware_feature_vector_directory = os.path.join(feature_vector_directory, "malware")
    benign_feature_vector_directory = os.path.join(feature_vector_directory, "benign")

    if not os.path.exists(feature_vector_directory):
        os.mkdir(feature_vector_directory)
        debug(f"[+] Feature vector directory has been created at : [bold green]{feature_vector_directory}",
              extra={"markup": True})

    if not os.path.exists(malware_feature_vector_directory):
        os.mkdir(malware_feature_vector_directory)
        debug(f"[+] Malicious feature vector path has been created at : [bold green]{malware_feature_vector_directory}",
              extra={"markup": True})

    if not os.path.exists(benign_feature_vector_directory):
        os.mkdir(benign_feature_vector_directory)
        debug("[+] Benign feature vector path has been created at : [bold green]{benign_feature_vector_directory}",
              extra={"markup": True})

    info("[+] Output directores have been setup ...\n")

    return malware_feature_vector_directory, benign_feature_vector_directory


def main():
    # Printing heading banner
    f = Figlet(font="banner4")
    grid = Table.grid(expand=True, padding=1, pad_edge=True)
    grid.add_column(justify="right", ratio=38)
    grid.add_column(justify="left", ratio=62)
    grid.add_row(
        Text.assemble((f.renderText("PE"), "bold red")),
        Text(f.renderText("Sidious"), "bold white"),
    )
    print(grid)
    print(
        Panel(
            Text.assemble(
                ("Creating Chaos with Mutated Evasive Malware with ", "grey"),
                ("Reinforcement Learning ", "bold red"),
                ("and "),
                ("Generative Adversarial Networks", "bold red"),
                justify="center",
            )
        )
    )

    # Read arguments and set logging configurations.
    args = parse_args()
    logging_setup(str(args.logfile), args.log)

    info("[bold red][*] Starting Feature Extraction Program ...\n", extra={"markup": True})

    info("[*] Setting parameters ...")
    debug(f"\t[*] Malware Directory - [bold green] {str(args.malware_path)}", extra={"markup": True})
    debug(f"\t[*] Benign Directory - [bold green]{str(args.benign_path)}", extra={"markup": True})
    debug(f"\t[*] Output Directory - [bold green]{str(args.output_dir)}", extra={"markup": True})
    debug(f"\t[*] Logfile - [bold green]{str(args.logfile)}", extra={"markup": True})
    debug(f"\t[*] Log Level - [bold green]{str(args.log)}", extra={"markup": True})
    info("[+] Parameteres set successfully ... \n")

    malware_path = str(args.malware_path)
    benign_path = str(args.benign_path)
    output_dir = str(args.output_dir)

    features_mapping_index(malware_path, benign_path, output_dir)

    info(f"[bold green][+] Feature Extraction module completed successfully ...", extra={"markup": True})

    list_output = "\n\t".join(
        [os.path.join(root, file) for root, directory, files in os.walk(args.output_dir) for file in files])
    info(f"The following files were created: \n[green] {list_output}", extra={"markup": True})
    pass


if __name__ == "__main__":
    main()
