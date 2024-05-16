
from pathlib import Path
import pickle
import numpy as np
import torch


feature_vectors = Path(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\benign_feature_set.pk')  # 恶意文件所在目录的路径
feature_vectors = pickle.load(open(feature_vectors, "rb"))
feature_vectors= [import_lib for import_lib in feature_vectors]
print(len(feature_vectors))
print(feature_vectors[0].shape)# torch.Size([12007])一个元素的导入表和节加起来有12007个，11472后是节

feature_section_vectors=[]
feature_import_vectors=[]

# 第二步：将序列分成两部分，这里简单地平均分配
for vector in feature_vectors[:100]:
    feature_section_vectors.append(vector[11473:])
    feature_import_vectors.append(vector[:11473])

# 将所有的 Tensor 转换为 NumPy 数组
section_numpy_array_list = [tensor.numpy() for tensor in feature_section_vectors]
import_numpy_array_list = [tensor.numpy() for tensor in feature_import_vectors]

# 将列表转换为 NumPy 数组
section_numpy_array = np.array(section_numpy_array_list)
import_numpy_array = np.array(import_numpy_array_list)
# print(section_numpy_array[0])
# print(len(section_numpy_array))
# 保存为 .npy 文件
np.save(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\benign_section_features_set', section_numpy_array)
np.save(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\benign_import_features_set', import_numpy_array)



feature_vectors = Path(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\feature_vector_mapping.pk')  # 恶意文件所在目录的路径
feature_vectors = pickle.load(open(feature_vectors, "rb"))
feature_vectors= [import_lib for import_lib in feature_vectors]

feature_section_feature_mapping=feature_vectors[11473:]
feature_import_feature_mapping=feature_vectors[:11473]


with open(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\feature_section_feature_mapping.pk', 'wb') as file1:
    pickle.dump(feature_section_feature_mapping, file1)

with open(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\feature_import_feature_mapping.pk', 'wb') as file2:
    pickle.dump(feature_import_feature_mapping, file2)

# 将所有的 Tensor 转换为 NumPy 数组
section_numpy_array_list =torch.numpy(feature_section_feature_mapping)
import_numpy_array_list = torch.numpy(feature_import_feature_mapping)

# 将列表转换为 NumPy 数组
section_numpy_array = np.array(section_numpy_array_list)
import_numpy_array = np.array(import_numpy_array_list)
# print(section_numpy_array[0])
# print(len(section_numpy_array))
# 保存为 .npy 文件
np.save(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\benign_section_features_set', section_numpy_array)
np.save(r'C:\Users\Depth\Desktop\信安赛\参考框架\AndersonMalware_rl\MalGAN\extract_features\feature_vector_directory\benign\benign_import_features_set', import_numpy_array)








