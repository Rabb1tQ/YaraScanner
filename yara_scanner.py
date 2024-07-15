import argparse
import concurrent.futures
import json
import os
from datetime import datetime

import yara
from tqdm import tqdm


# 定义一个函数来加载目录下所有的YARA规则
def load_rules(directory):
    count = 0
    rules = []

    if os.path.isfile(directory):
        rules.append(yara.compile(directory))
    else:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.yar'):
                    try:
                        # 单线程编译规则
                        rules.append(yara.compile(os.path.join(root, file)))
                    except yara.SyntaxError as e:
                        count = count + 1

    print("共编译错误" + str(count) + "条")
    print("共编译成功" + str(len(rules)) + "条")
    return rules


# 定义一个函数来扫描单个文件
def scan_file(file_path, rule):
    try:
        matches = rule.match(file_path)

        matched_rules = []
        if matches:
            for match in matches:
                # 将匹配到的规则信息添加到列表中
                matched_rules.append(
                    {
                        'rule': match.rule,
                        'meta': match.meta,
                        'strings':
                            [
                                {
                                    'byte': ' '.join(hex(byte)[2:] for byte in s[2]),
                                    'string_data': s[2].decode('utf-8'),
                                    'offset': s[0]
                                }
                                for s in match.strings
                            ]
                    }
                )
            result = {
                'file': file_path,
                'matched_rules': matched_rules
            }
            return result
        return matched_rules
    except Exception as e:
        print(f'Error scanning {file_path}: {e}')
    return None


# 定义一个函数来分批处理文件扫描
def batch_scan_files(file_paths, rules, batch_size):
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        # 分批处理文件
        for i in range(0, len(file_paths), batch_size):
            batch = file_paths[i:i + batch_size]
            # 使用线程池来并发地扫描文件
            futures = [executor.submit(scan_file, file_path, rule) for file_path in batch for rule in rules]
            for future in concurrent.futures.as_completed(futures):
                yield future.result()


# 定义一个函数来遍历目录并扫描文件
def scan_directory(target_dir, rules, output, json_filename):
    # 计算总的文件数量
    total_files = sum(len(files) for _, _, files in os.walk(target_dir))
    progress_bar = tqdm(total=total_files, desc="Scanning directory", position=0)

    if os.path.isfile(target_dir):
        all_files = [target_dir]
    else:
        # 获取所有文件路径
        all_files = [os.path.join(root, file) for root, dirs, files in os.walk(target_dir) for file in files]

    # 分批处理文件并扫描
    matches = []
    for match in batch_scan_files(all_files, rules, batch_size=100):
        if match:
            matches.append(match)

    # 累积匹配结果并写入文件或打印
    if output:
        with open(json_filename, 'w') as f:
            for match in matches:
                json.dump(match, f, indent=2)
    else:
        for match in matches:
            print(match)

    progress_bar.update(len(all_files))


# 主函数
def main(rule_dir, target_dir, output):
    # 加载目录下所有的YARA规则
    rules = load_rules(rule_dir)

    # 扫描目录中的所有文件
    now = datetime.now()
    json_filename = now.strftime("%Y-%m-%d_%H-%M-%S-") + 'result.json'
    if output and not os.path.exists(json_filename):
        with open(json_filename, 'w') as file:
            pass
    scan_directory(target_dir, rules, output, json_filename)
    if output:
        print('已输出到文件：' + json_filename)


# 定义命令行参数解析器
parser = argparse.ArgumentParser(description='YARA Scanner')
parser.add_argument('-r', '--rule_dir', help='YARA rules directory', required=True)
parser.add_argument('-t', '--target_dir', help='Target directory to scan', required=True)
parser.add_argument('-o', '--output', help='Write results to file', action='store_true')

# 解析命令行参数
args = parser.parse_args()

# 运行主函数
if __name__ == "__main__":
    main(args.rule_dir, args.target_dir, args.output)
