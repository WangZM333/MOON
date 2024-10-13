import zerorpc
import numpy as np
import threading

class AggregateServer(object):
    def __init__(self, num_clients):
        self.num_clients = num_clients          # 客户端数量
        self.gradients = []                     # 存储所有客户端提交的梯度
        self.lock = threading.Lock()            # 线程锁
        self.sum_ready = False                  # 标记是否已经计算了梯度总和
        self.sum = None                         # 存储梯度总和
        self.condition = threading.Condition()   # 通知等待的线程

    def process_gradients(self):
        print("开始计算总和。")
        self.sum = np.sum(self.gradients, axis=0)
        self.sum_ready = True
        with self.condition:
            self.condition.notify_all()  # 通知等待的客户端
        print("所有梯度计算完成，服务器即将关闭。")
        self.shutdown_server()

    def submit_gradient(self, client_id, gradient):
        with self.lock:
            print(f"收到来自客户端 {client_id} 的梯度数据。")
            self.gradients.append(np.array(gradient))
            if len(self.gradients) == self.num_clients:
                threading.Thread(target=self.process_gradients).start()
        return "梯度已收到"


    def get_sum(self, client_id):
        """
        返回梯度总和。如果总和尚未准备好，则等待。
        """
        with self.lock:
            if self.sum_ready:
                return self.sum.tolist()
            else:
                print(f"客户端 {client_id} 正在等待梯度总和。")
                with self.condition:
                    while not self.sum_ready:
                        self.condition.wait()  # 等待服务器计算完总和
                return self.sum.tolist()

    def shutdown_server(self):
        print("关闭服务器进程...")
        sys.exit(0)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("命令: python server.py <客户端数量>")
        sys.exit(1)
    num_clients = int(sys.argv[1])
    server = AggregateServer(num_clients)
    s = zerorpc.Server(server)
    s.bind("tcp://0.0.0.0:4242")
    print(f"服务器已启动，等待 {num_clients} 个客户端的连接。")
    s.run()

'''
python server.py 10
'''