import copy
import math
import os
import signal
import threading
import time
import zerorpc
from ECIES import *
from phe.paillier import generate_paillier_keypair
import sys
import pickle

class TrustedParty:
    def __init__(self, num_clients):
        self.clients_info = []  # 存储所有客户端的信息
        self.num_clients = num_clients
        self.groups = None
        self.sec_shuffle = None
        self.messages_sent = 0
        self.lock = threading.Lock()
        # self.ip = "192.168.1.100"

    def generate_client_info(self):
        for i in range(self.num_clients):
            client_id = str(i + 1)
            ip_address = f"192.168.1.{client_id}"
            private_key, public_key = make_keypair()
            paillier_pk, paillier_sk = generate_paillier_keypair(n_length=1024)  # Paillier密钥加密种子
            self.clients_info.append((client_id, ip_address, public_key, private_key, paillier_pk, paillier_sk))
            print(f"生成客户端 {client_id}，IP: {ip_address}")

    def group_clients(self):
        num_groups = int(math.sqrt(self.num_clients))  # 计算组数
        group_info = copy.deepcopy(self.clients_info)
        random.shuffle(group_info)  # 打乱客户端信息顺序
        groups = [[] for _ in range(num_groups)]  # 初始化组列表
        sec_shuffle = []

        # 均匀分配客户端到组
        for idx, client in enumerate(group_info):
            group_index = idx % num_groups  # 确定组的索引
            # groups[group_index].append(client)
            client_id, ip_address, public_key, _, paillier_pk, _ = client  # 解包信息
            groups[group_index].append((client_id, ip_address, public_key, paillier_pk))

        for group in groups:
            if group:  # 确保组不为空
                sec_shuffle.append(group[-1])  # 添加最后一个客户端

        self.groups = groups
        self.sec_shuffle = sec_shuffle
        print(f"group info: {groups}")
        print(f"seconde shuffle: {sec_shuffle}")


    def get_client_info(self, client_id):
        # 返回指定客户端的信息（包括公私钥）
        all_client_info = copy.deepcopy(self.clients_info)
        for info in self.clients_info:
            if info[0] == client_id:
                print(f"收到客户端{client_id}的请求")
                # 查找客户端所在的组并发送信息
                for group_index, group in enumerate(self.groups):
                    for client in group:
                        if client[0] == client_id:  # 检查客户端 ID
                            # 发送所在组的信息给客户端
                            group_info = group

                with self.lock:
                    self.messages_sent += 1

                return {
                    "self_info": pickle.dumps({
                        "client_id": info[0],
                        "ip_address": info[1],
                        "public_key": info[2],
                        "private_key": info[3],
                        "paillier_pk": info[4],
                        "paillier_sk": info[5]
                    }),
                    "all_clients_info": pickle.dumps([
                        {
                            "client_id": c[0],
                            "ip_address": c[1],
                            "public_key": c[2],
                            "paillier_pk": c[4]
                        } for c in all_client_info
                    ]),
                    "group_info": pickle.dumps([
                        {
                            "client_id": c[0],
                            "ip_address": c[1],
                            "public_key": c[2],
                            "paillier_pk": c[3]
                        } for c in group_info
                    ]),
                    "sec_shuffle_info": pickle.dumps([
                        {
                            "client_id": c[0],
                            "ip_address": c[1],
                            "public_key": c[2],
                            "paillier_pk": c[3]
                        } for c in self.sec_shuffle
                    ])
                }

        return None

    def stop_server(self):
        while self.messages_sent < self.num_clients:
            time.sleep(2)
        print("初始化完成")
        pid = os.getpid()  # 获取当前进程的PID
        os.kill(pid, signal.SIGTERM)  # 主动结束指定ID的程序运行


    def run(self):
        self.generate_client_info()
        self.group_clients()
        print("初始化中...")
        stop_thread = threading.Thread(target=self.stop_server)
        stop_thread.start()
        server = zerorpc.Server(self)
        server.bind("tcp://0.0.0.0:4241")
        server.run()

        # 结束服务
        server.stop()  # 停止服务器


'''
python trusted_party.py 100
'''


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python trusted_party.py <客户端数量>")
        sys.exit(1)

    num_clients = int(sys.argv[1])
    # num_clients = 10
    trusted_party = TrustedParty(num_clients)
    trusted_party.run()