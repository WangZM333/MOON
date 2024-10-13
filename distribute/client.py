import zerorpc
import numpy as np
import threading
import sys
import time


def run_client(client_id, gradient_size, server_address):
    """
    每个客户端执行的逻辑：生成梯度并发送给服务器。
    """
    client = zerorpc.Client()
    client.connect(server_address)

    # 随机生成梯度
    gradient = np.random.rand(gradient_size).tolist()

    print(f"客户端 {client_id} 生成了梯度: {gradient}")

    # 发送梯度到服务器
    response = client.submit_gradient(client_id, gradient)
    print(f"客户端 {client_id} 发送了梯度: {response}")

    # 等待接收梯度总和
    sum_gradient = client.get_sum(client_id)
    print(f"客户端 {client_id} 收到了梯度总和: {sum_gradient}")


def main():
    if len(sys.argv) != 4:
        print("用法: python client.py <客户端数量> <梯度大小> <服务器地址>")
        sys.exit(1)

    # 从命令行参数获取客户端数量、梯度大小、服务器地址
    num_clients = int(sys.argv[1])
    gradient_size = int(sys.argv[2])
    server_address = sys.argv[3]

    # 启动多个客户端，每个客户端作为一个线程
    threads = []
    for i in range(num_clients):
        client_id = f"client{i + 1}"
        thread = threading.Thread(target=run_client, args=(client_id, gradient_size, server_address))
        threads.append(thread)
        thread.start()

    # 等待所有线程完成
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()

'''
python client.py 10 100000 tcp://127.0.0.1:4242
'''