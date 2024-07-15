# yara 扫描工具

## Description

下载官方的可执行文件不好使，没法指定某目录下的所有yara规则，当然也可能是我的用法有问题吧，不过我懒得研究了，顺手敲个轮子吧~

## Usage

```shell
git clone --recurse-submodules git@github.com:Rabb1tQ/YaraScanner.git
cd YaraScanner
pip install -r requirements.txt
python yara_scanner.py
  yara_scanner.py [-h] -r RULE_DIR -t TARGET_DIR [-o]
  yara_scanner.py: error: the following arguments are required: -r/--rule_dir, -t/--target_dir
```

## Example

```shell
python yara_scanner.py -r rules-master -t artifact.exe -o
```

