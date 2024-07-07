import re
import matplotlib.pyplot as plt

# 定义读取日志文件的函数
def read_accuracy_from_log(log_file):
    accuracies = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'Global Model Test accuracy:\s+(\d+\.\d+)', line)
            if match:
                accuracies.append(float(match.group(1)))
    return accuracies

# 读取两个日志文件中的准确率
log_file1 = 'logs/experiment_log-2024-06-22-2312-32.log'
log_file2 = 'logs/experiment_log-2024-06-25-1708-08.log'

accuracies1 = read_accuracy_from_log(log_file1)
accuracies2 = read_accuracy_from_log(log_file2)

# 确保两个文件中的数据点数量一致
min_length = min(len(accuracies1), len(accuracies2))
accuracies1 = accuracies1[:min_length]
accuracies2 = accuracies2[:min_length]

# 绘制图表
plt.figure(figsize=(10, 5))
plt.plot(accuracies1, label='fedavg')
plt.plot(accuracies2, label='inner')
plt.xlabel('Epoch')
plt.ylabel('Global Model Train Accuracy')
plt.title('Global Model Train Accuracy Over Epochs')
plt.legend()
plt.grid(True)
plt.show()