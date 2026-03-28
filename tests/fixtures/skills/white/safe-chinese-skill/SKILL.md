# 安全中文技能

一个提供文件分析和报告生成功能的安全技能。

## 功能描述

本技能提供了以下功能：
- 文件内容分析
- 统计信息生成
- 报告格式化输出

## 使用方法

```python
from utils import analyze_file
result = analyze_file("/path/to/file.txt")
print(f"文件行数: {result['lines']}")
print(f"文件大小: {result['size']} 字节")
```

## 权限要求

本技能只需要目标文件的读取权限，不会修改任何文件。

## 注意事项

- 请确保有足够的磁盘空间用于临时文件
- 分析大文件时可能需要较长时间

## 作者

张三 <zhangsan@example.com>

## 版本

1.0.0
