# 日志设置和训练时候的日志记录

import copy
import logging
import sys
from _decimal import Decimal
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union, Any

import torch
from torch import Tensor

ListOrInt = Union[int, List[int]]

LOG_DIR = Path(".")# 当前目录
IS_CUDA = torch.cuda.is_available()

'''日志设置
quiet_mode：是否静音（不在控制台打印日志信息）
log_level:日志级别
job_id:可选识别日志的id
'''
def setup_logger(quiet_mode: bool, log_level: int = logging.DEBUG,
                 job_id: Optional[ListOrInt] = None) -> None:
    r"""
    Logger Configurator

    Configures the test logger.

    :param quiet_mode: True if quiet mode (i.e., disable logging to stdout) is used
    :param job_id: Identification number for the job
    :param log_level: Level to log
    """
    #date_format = '%m/%d/%Y %I:%M:%S %p'  # Example Time Format - 12/12/2010 11:46:36 AM
    date_format = '%Y-%m-%d_%H-%M-%S'    # 定义日志的日期格式和日志消息的格式字符串
    format_str = '%(asctime)s -- %(levelname)s -- %(message)s'
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    flds = ["logs"]

    if job_id is not None:
        if isinstance(job_id, int):
            job_id = [job_id]
        flds += ["_j=", "-".join("%05d" % x for x in job_id)]

    # Use datetime.now() with strftime to format the timestamp correctly
    filename_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    flds += ["_", filename_time, ".log"]

    filename = LOG_DIR / "".join(flds)
    print("Logging to file:", filename)
    logging.basicConfig(filename=filename, level=log_level, format=format_str, datefmt=date_format)
    # 设置日志配置

    # Also print to stdout
    if not quiet_mode:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(format_str)
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
    # 如果不是静音模式，则将日志标准化输出到控制台

    logging.info("******************* New Run Beginning *****************")
    logging.debug("CUDA: %s", "ENABLED" if IS_CUDA else "Disabled")
    logging.info(" ".join(sys.argv))
    # 日志开始时运行的消息，CUD状态和参数



# 标准化训练过程的日志记录
'''示例：
# 日志配置
setup_logger(quiet_mode=False, job_id=12345)

# 设定日志字段名
field_names = ["Loss", "Accuracy", "Learning Rate"]
# 创建 TrainingLogger 实例
logger = TrainingLogger(fld_names=field_names)

# 假设有以下训练数据
epochs = 10
for epoch in range(1, epochs + 1):
    # 这里只是模拟数据
    loss = 0.01 * (epochs - epoch)  # 损失随epoch逐渐减小
    accuracy = 0.75 + 0.02 * epoch  # 准确率逐渐提高
    learning_rate = 0.001 * (1 / epoch)  # 学习率递减

    # 记录当前epoch的数据
    logger.log(epoch, [loss, accuracy, learning_rate])
    输出为：
Epoch     Loss       Accuracy    Learning Rate  
------------------------------------------------
  1      0.0900     0.7700       0.0010      
  2      0.0800     0.7900       0.0005      
  3      0.0700     0.8100       0.0003   '''

class TrainingLogger:
    r""" Helper class used for standardizing logging """
    FIELD_SEP = " "
    DEFAULT_WIDTH = 12
    EPOCH_WIDTH = 5

    DEFAULT_FIELD = None

    LOG = logging.info# 输出日志信息

    def __init__(self, fld_names: List[str], fld_widths: Optional[List[int]] = None):
        if fld_widths is None: fld_widths = len(fld_names) * [TrainingLogger.DEFAULT_WIDTH]
        if len(fld_widths) != len(fld_names):
            raise ValueError("Mismatch in the length of field names and widths")

        self._log = TrainingLogger.LOG  # Function used for logging
        self._fld_widths = fld_widths

        # Print the column headers
        combined_names = ["Epoch"] + fld_names
        combined_widths = [TrainingLogger.EPOCH_WIDTH] + fld_widths
        fmt_str = TrainingLogger.FIELD_SEP.join(["{:^%d}" % _d for _d in combined_widths])
        self._log(fmt_str.format(*combined_names))
        # Line of separators under the headers (default value is hyphen)
        sep_line = TrainingLogger.FIELD_SEP.join(["{:-^%d}" % _w for _w in combined_widths])
        logging.info(sep_line.format(*(len(combined_widths) * [""])))

    @property
    def num_fields(self) -> int:
        r""" Number of fields to log """
        return len(self._fld_widths)

    def log(self, epoch: int, values: List[Any]) -> None:
        r""" Log the list of values """
        values = self._clean_values_list(values)
        format_str = self._build_values_format_str(values)
        self._log(format_str.format(epoch, *values))

    def _build_values_format_str(self, values: List[Any]) -> str:
        r""" Constructs a format string based on the values """
        def _get_fmt_str(_w: int, fmt: str) -> str:
            return "{:^%d%s}" % (_w, fmt)

        frmt = [_get_fmt_str(self.EPOCH_WIDTH, "d")]
        for width, v in zip(self._fld_widths, values):
            if isinstance(v, str): fmt_str = "s"
            elif isinstance(v, Decimal): fmt_str = ".3E"
            elif isinstance(v, int): fmt_str = "d"
            elif isinstance(v, float): fmt_str = ".4f"
            else: raise ValueError("Unknown value type")

            frmt.append(_get_fmt_str(width, fmt_str))
        return TrainingLogger.FIELD_SEP.join(frmt)

    def _clean_values_list(self, values: List[Any]) -> List[Any]:
        r""" Modifies values in the \p values list to make them straightforward to log """
        values = copy.deepcopy(values)
        # Populate any missing fields
        while len(values) < self.num_fields:
            values.append(TrainingLogger.DEFAULT_FIELD)

        new_vals = []
        for v in values:
            if isinstance(v, bool): v = "+" if v else ""
            elif v is None: v = "N/A"
            elif isinstance(v, Tensor): v = v.item()

            # Must be separate since v can be a float due to a Tensor
            if isinstance(v, float) and (v <= 1E-3 or v >= 1E4): v = Decimal(v)
            new_vals.append(v)
        return new_vals
