import zerorpc
import numpy as np
import sys
import time


def main():
    if len(sys.argv) != 4:
        print("命令: python client.py <客户端ID> <梯度大小> <服务器地址>")
        print("e.g.: python client.py client1 10 tcp://127.0.0.1:4242")
        sys.exit(1)

    client_id = sys.argv[1]
    gradient_size = int(sys.argv[2])
    server_address = sys.argv[3]

    # 连接到服务器
    client = zerorpc.Client(heartbeat=60)
    client.connect(server_address)

    # 生成随机梯度
    gradient = np.random.randn(gradient_size)
    print(f"客户端 {client_id} 生成的梯度: {gradient}")

    # 提交梯度到服务器
    response = client.submit_gradient(client_id, gradient.tolist())
    print(f"客户端 {client_id} 提交梯度的响应: {response}")

    # 获取梯度总和
    sum_gradient = client.get_sum(client_id)
    print(f"客户端 {client_id} 接收到的梯度总和: {sum_gradient}")


if __name__ == "__main__":
    main()
