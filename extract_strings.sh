#!/bin/bash

# 指定包含二进制文件的目录
BINARY_DIR="./malware_rl/envs/controls/trusted/all_benign/benign"
# 指定输出目录
OUTPUT_DIR="./malware_rl/envs/controls/good_strings"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 遍历目录中的所有文件
for binary in "$BINARY_DIR"/*
do
  # 使用basename获取文件名，不包括路径
  filename=$(basename "$binary")
  # 使用strings命令处理每个文件，并将结果保存到对应的.txt文件
  strings "$binary" > "$OUTPUT_DIR/${filename}.txt"
done
