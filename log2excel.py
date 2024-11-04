import re
import pandas as pd

# 日志文件路径
folder_path = "mask_shuffle_log/1_100000_10"
file_name = "experiment_info.log"

# 定义正则表达式模式
patterns = {
    "Mask Shuffle Times": r"Mask Shuffle Times\(s\): \[(.*?)\]",
    "Group Shuffle Times": r"Group Shuffle Times\(s\): \[(.*?)\]",
    "Send Seed Times": r"Send Seed Times\(ms\): \[(.*?)\]",
    "Send Second Seed Times": r"Send Second Seed Times\(ms\): \[(.*?)\]",
    "Seed Sizes": r"Seed Sizes\(KB\): \[(.*?)\]",
    "Second Seed Sizes": r"Second Seed Sizes\(KB\): \[(.*?)\]",
    "Masking Times": r"Masking Times\(ms\): \[(.*?)\]",
    "Hash Calculation Times": r"Hash Calculation Times\(ms\): \[(.*?)\]",
    "Send Grad Times": r"Send Grad Times\(ms\): \[(.*?)\]",
    "Grad Sizes": r"Grad Sizes\(MB\): \[(.*?)\]",
    "Aggregation Times": r"Aggregation Times\(ms\): \[(.*?)\]",
    "Verification Times": r"Verification Times\(ms\): \[(.*?)\]",
    "Start Times": r"Start Times: \[(.*?)\]",

    "group_shuffle_start_times": r"group_shuffle_start_times \[(.*?)\]",
    "mask_shuffle_start_times": r"mask_shuffle_start_times \[(.*?)\]",
    "add_mask_times": r"add_mask_times \[(.*?)\]",
    "hash_calculation_start_times": r"hash_calculation_start_times \[(.*?)\]",
    "send_grad_start_times": r"send_grad_start_times \[(.*?)\]",
    "aggregation_start_time": r"aggregation_start_time \[(.*?)\]",
    "broadcast_start_time": r"broadcast_start_time \[(.*?)\]",
    "verify_times": r"verify_times \[(.*?)\]",

    "End Times": r"End Times: \[(.*?)\]",

    "Run Times": r"Run Times\(s\): \[(.*?)\]",
    "Total Run Time": r"Total Run Time\(s\): (.+)"
}

# 存储提取的数据
extracted_data = {}

# 读取日志文件
with open(f"{folder_path}/{file_name}", 'r') as file:
    log_content = file.read()

    for key, pattern in patterns.items():
        match = re.search(pattern, log_content)
        if match:
            # 提取数据并转换为列表
            data_str = match.group(1).replace(' ', '').split(',')
            # 过滤空字符串并转换为浮点数
            extracted_data[key] = [float(x) for x in data_str if x]

# 创建 DataFrame 并写入 Excel 文件
df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in extracted_data.items()]))
df.to_excel(f"{folder_path}/experiment_data.xlsx", index=False)

print("数据已成功提取并写入到 Excel 文件中。")

