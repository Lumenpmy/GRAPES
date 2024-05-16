import datetime
from pathlib import Path
from typing import Union

import numpy as np

import torch
from sklearn.metrics import confusion_matrix, roc_auc_score

TensorOrFloat = Union[torch.Tensor, float]
TorchOrNumpy = Union[torch.Tensor, np.ndarray]


# noinspection PyProtectedMember,PyUnresolvedReferences
def _export_results(model: 'MalGAN', valid_loss: TensorOrFloat, test_loss: TensorOrFloat,
                    avg_num_bits_changed: TensorOrFloat, y_actual: TorchOrNumpy,
                    y_mal_orig: TorchOrNumpy, y_prob: TorchOrNumpy, y_hat: TorchOrNumpy) -> str:
    r"""
    Exports MalGAN results.

    :param model: MalGAN model
    :param valid_loss: Average loss on the malware validation set
    :param test_loss: Average loss on the malware test set
    :param avg_num_bits_changed:
    :param y_actual: Actual labels
    :param y_mal_orig: Predicted value on the original (unmodified) malware
    :param y_prob: Probability of malware
    :param y_hat: Predict labels
    :return: Results string
    """
    if isinstance(y_prob, torch.Tensor):# 判断y_prob是不是tensor类型
        y_prob = y_prob.numpy()
    if isinstance(y_mal_orig, torch.Tensor):
        y_mal_orig = y_mal_orig.numpy()
    if isinstance(y_actual, torch.Tensor):  # 判断y_prob是不是tensor类型
        y_actual = y_actual.numpy()
    if isinstance(y_hat, torch.Tensor):  # 判断y_prob是不是tensor类型
        y_hat = y_hat.numpy()


    results_file = Path("results.csv")
    exists = results_file.exists()
    with open(results_file, "a+") as f_out:
        header = ",".join(["time_completed,M,Z,batch_size,test_set_size,detector_type,activation",
                           "gen_hidden_dim,discim_hidden_dim",
                           "avg_validation_loss,avg_test_loss,avg_num_bits_changed",
                           "auc,orig_mal_detect_rate,mod_mal_detect_rate,ben_mal_detect_rate"])
        # 这行使用 with 语句打开文件。open 函数的第一个参数是文件名，第二个参数 “$a+$” 是文件打开模式。
        # “$a+$” 模式表示如果文件不存在，就创建文件；
        # 如果文件存在，就在文件末尾追加内容。同时，“$a+$” 模式也允许读取文件内容
        if not exists:
            f_out.write(header)

        results = ["\n%s" % datetime.datetime.now(),
                   "%d,%d" % (model.M, model.Z),
                   "%d,%s,%s" % (len(y_actual), model._bb.type.name, model._g.__class__.__name__),
                   "\"%s\",\"%s\"" % (str(model.d_gen), str(model.d_discrim)),
                   "%.15f,%.15f,%.3f" % (valid_loss, test_loss, avg_num_bits_changed)]

        auc = roc_auc_score(y_actual, y_prob)
        results.append("%.8f" % auc)

        # Calculate the detection rate on unmodified malware
        results.append("%.8f" % y_mal_orig.mean())

        # Write the TxR and NxR information
        tn, fp, fn, tp = confusion_matrix(y_actual, y_hat).ravel()
        tpr, fpr = tp / (tp + fn), fp / (tn + fp)
        for rate in [tpr, fpr]:
            results.append("%.8f" % rate)
        results = ",".join(results)
        f_out.write(results)

        return "".join([header, results])
