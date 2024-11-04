import os
import re


# 设置日志文件夹路径
log_folder = 'mask_shuffle_log/1_100000_10'
# 创建一个新的日志文件以存储提取的信息
output_log_file = os.path.join(log_folder, 'experiment_info.log')

# 用于存储提取信息的列表
mask_shuffle_times = []
group_shuffle_times = []
masking_times = []
hash_calculation_times = []
aggregation_times = []
verification_times = []
start_times = []
end_times = []
send_seed_times = []
send_second_seed_times = []
seed_sizes = []
second_seed_sizes = []
send_grad_times = []
grad_sizes = []
run_times = []

group_shuffle_start_times = []
mask_shuffle_start_times = []
add_mask_times = []
hash_calculation_start_times = []
send_grad_start_times = []
aggregation_start_time = []
aggregation_end_time = []
broadcast_start_time = []
verify_times = []


# 遍历文件夹中的所有文件
for filename in os.listdir(log_folder):
    # 检查文件名是否符合规则
    if filename.startswith('client_') and filename.endswith('.log'):
        filepath = os.path.join(log_folder, filename)
        with open(filepath, 'r') as file:
            content = file.readlines()

            for line in content:
                # 使用正则表达式提取所需的信息
                if "运行 group shuffle 总时间" in line:
                    time = re.search(r"时间 ([\d.]+) s", line)
                    if time:
                        group_shuffle_times.append(float(time.group(1)))

                elif "运行 mask shuffle 总时间" in line:
                    time = re.search(r"时间 ([\d.]+) s", line)
                    if time:
                        mask_shuffle_times.append(float(time.group(1)))

                elif "向梯度添加掩码耗时" in line:
                    time = re.search(r"耗时 ([\d.]+) ms", line)
                    if time:
                        masking_times.append(float(time.group(1)))

                elif "发送种子密文耗时" in line:
                    time = re.search(r"客户端\d+发送种子密文耗时([\d.]+)ms, 种子密文数据大小([\d.]+) KB", line)
                    if time:
                        send_seed_times.append(float(time.group(1)))
                        seed_sizes.append(float(time.group(2)))


                elif "发送第二轮种子密文耗时" in line:
                    time = re.search(r"客户端\d+发送第二轮种子密文耗时([\d.]+)ms, 第二轮种子密文数据大小([\d.]+) KB", line)
                    if time:
                        send_second_seed_times.append(float(time.group(1)))
                        second_seed_sizes.append(float(time.group(2)))

                elif "发送梯度数据耗时" in line:
                    time = re.search(r"客户端\d+发送梯度数据耗时([\d.]+)ms, 梯度数据大小([\d.]+) MB", line)
                    if time:
                        send_grad_times.append(float(time.group(1)))
                        grad_sizes.append(float(time.group(2)))

                elif "计算本地梯度同态哈希值耗时" in line:
                    time = re.search(r"耗时 ([\d.]+) ms", line)
                    if time:
                        hash_calculation_times.append(float(time.group(1)))

                elif "聚合节点聚合梯度数据耗时" in line:
                    time = re.search(r"耗时([\d.]+)ms", line)
                    if time:
                        aggregation_times.append(float(time.group(1)))

                elif "验证聚合梯度耗时" in line:
                    time = re.search(r"耗时([\d.]+) ms", line)
                    if time:
                        verification_times.append(float(time.group(1)))

                elif "启动时间：" in line:
                    time = re.search(r"启动时间：([\d.]+)", line)
                    if time:
                        start_times.append(float(time.group(1)))

                elif "结束时间：" in line:
                    time = re.search(r"结束时间：([\d.]+)", line)
                    if time:
                        end_times.append(float(time.group(1)))

                elif "运行时间：" in line:
                    time = re.search(r"运行时间：([\d.]+) s", line)
                    if time:
                        run_times.append(float(time.group(1)))

                elif "开始运行 group shuffle 时间：" in line:
                    time = re.search(r"开始运行 group shuffle 时间：([\d.]+)", line)
                    if time:
                        group_shuffle_start_times.append(float(time.group(1)))

                elif "开始运行 mask shuffle 时间：" in line:
                    time = re.search(r"开始运行 mask shuffle 时间：([\d.]+)", line)
                    if time:
                        mask_shuffle_start_times.append(float(time.group(1)))

                elif "添加掩码时间：" in line:
                    time = re.search(r"添加掩码时间：([\d.]+)", line)
                    if time:
                        add_mask_times.append(float(time.group(1)))

                elif "计算同态哈希时间：" in line:
                    time = re.search(r"计算同态哈希时间：([\d.]+)", line)
                    if time:
                        hash_calculation_start_times.append(float(time.group(1)))
                        #
                elif "发送梯度并等待时间：" in line:
                    time = re.search(r"发送梯度并等待时间：([\d.]+)", line)
                    if time:
                        send_grad_start_times.append(float(time.group(1)))


                elif "开始聚合梯度时间：" in line:
                    time = re.search(r"开始聚合梯度时间：([\d.]+)", line)
                    if time:
                        aggregation_start_time.append(float(time.group(1)))


                elif "开始广播梯度时间：" in line:
                    time = re.search(r"开始广播梯度时间：([\d.]+)", line)
                    if time:
                        broadcast_start_time.append(float(time.group(1)))

                elif "开始验证时间：" in line:
                    time = re.search(r"开始验证时间：([\d.]+)", line)
                    if time:
                        verify_times.append(float(time.group(1)))



earlist_time = min(start_times)
latest_time = max(end_times)
total_run_time = latest_time - earlist_time

for i in range(len(group_shuffle_start_times)):
    group_shuffle_start_times[i] -= earlist_time

for i in range(len(mask_shuffle_start_times)):
    mask_shuffle_start_times[i] -= earlist_time

for i in range(len(add_mask_times)):
    add_mask_times[i] -= earlist_time

for i in range(len(hash_calculation_start_times)):
    hash_calculation_start_times[i] -= earlist_time

for i in range(len(send_grad_start_times)):
    send_grad_start_times[i] -= earlist_time


for i in range(len(aggregation_start_time)):
    aggregation_start_time[i] -= earlist_time


for i in range(len(broadcast_start_time)):
    broadcast_start_time[i] -= earlist_time

for i in range(len(verify_times)):
    verify_times[i] -= earlist_time

for i in range(len(end_times)):
    end_times[i] -= earlist_time

# 输出结果
print("Mask Shuffle Times(s):", mask_shuffle_times)
print("Group Shuffle Times(s):", group_shuffle_times)
print("Send Seed Times(ms):", send_seed_times)
print("Send Second Seed Times(ms):", send_second_seed_times)
print("Seed Sizes(KB):", seed_sizes)
print("Second Seed Sizes(KB):", second_seed_sizes)
print("Masking Times:(ms)", masking_times)
print("Hash Calculation Times(ms):", hash_calculation_times)
print("Send Grad Times(ms):", send_grad_times)
print("Grad Sizes(MB):", grad_sizes)
print("Aggregation Times(ms):", aggregation_times)
print("Verification Times(ms):", verification_times)
print("Start Times:", start_times)

print(f"group_shuffle_start_times: {group_shuffle_start_times}")
print(f"mask_shuffle_start_times: {mask_shuffle_start_times}")
print(f"add_mask_times: {add_mask_times}")
print(f"hash_calculation_start_times: {hash_calculation_start_times}")
print(f"send_grad_start_times: {send_grad_start_times}")
print(f"aggregation_start_time: {aggregation_start_time}")
print(f"broadcast_start_time: {broadcast_start_time}")
print(f"verify_times: {verify_times}")


print("End Times:", end_times)
print("Run Times(s):", run_times)
print("Total Run Time(s):", total_run_time)


with open(output_log_file, 'w') as log_file:
    log_file.write("Mask Shuffle Times(s): {}\n".format(mask_shuffle_times))
    log_file.write("Group Shuffle Times(s): {}\n".format(group_shuffle_times))
    log_file.write("Send Seed Times(ms): {}\n".format(send_seed_times))
    log_file.write("Send Second Seed Times(ms) {}\n".format(send_second_seed_times))
    log_file.write("Seed Sizes(KB): {}\n".format(seed_sizes))
    log_file.write("Second Seed Sizes(KB): {}\n".format(second_seed_sizes))
    log_file.write("Masking Times(ms): {}\n".format(masking_times))
    log_file.write("Hash Calculation Times(ms): {}\n".format(hash_calculation_times))
    log_file.write("Send Grad Times(ms): {}\n".format(send_grad_times))
    log_file.write("Grad Sizes(MB): {}\n".format(grad_sizes))
    log_file.write("Aggregation Times(ms): {}\n".format(aggregation_times))
    log_file.write("Verification Times(ms): {}\n".format(verification_times))
    log_file.write("Start Times: {}\n".format(start_times))
    log_file.write("End Times: {}\n".format(end_times))

    log_file.write("group_shuffle_start_times {}\n".format(group_shuffle_start_times))
    log_file.write("mask_shuffle_start_times {}\n".format(mask_shuffle_start_times))
    log_file.write("add_mask_times {}\n".format(add_mask_times))
    log_file.write("hash_calculation_start_times {}\n".format(hash_calculation_start_times))
    log_file.write("send_grad_start_times {}\n".format(send_grad_start_times))
    log_file.write("aggregation_start_time {}\n".format(aggregation_start_time))
    log_file.write("broadcast_start_time {}\n".format(broadcast_start_time))
    log_file.write("verify_times {}\n".format(verify_times))

    log_file.write("Run Times(s): {}\n".format(run_times))
    log_file.write("Total Run Time(s): {}\n".format(total_run_time))

