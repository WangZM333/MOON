import copy

import zerorpc
from ECIES import *
from phe.paillier import generate_paillier_keypair
import sys
import pickle

class TrustedParty:
    def __init__(self, num_clients):
        self.clients_info = []  # 存储所有客户端的信息
        self.num_clients = num_clients
        # self.ip = "192.168.1.100"

    def generate_client_info(self):
        for i in range(self.num_clients):
            client_id = str(i + 1)
            ip_address = f"192.168.1.{client_id}"
            private_key, public_key = make_keypair()
            paillier_pk, paillier_sk = generate_paillier_keypair(n_length=1024)  # Paillier密钥加密种子
            self.clients_info.append((client_id, ip_address, public_key, private_key, paillier_pk, paillier_sk))
            print(f"生成客户端 {client_id}，IP: {ip_address}")

    def get_client_info(self, client_id):
        # 返回指定客户端的信息（包括公私钥）
        all_client_info = copy.deepcopy(self.clients_info)
        for info in self.clients_info:
            if info[0] == client_id:
                print(f"收到客户端{client_id}的请求")
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
                    ])
                }
        return None

    def get_all_clients_info(self):
        return self.clients_info

    def run(self):
        self.generate_client_info()
        print("初始化中...")
        server = zerorpc.Server(self)
        server.bind("tcp://0.0.0.0:4241")
        server.run()
        print("初始化完成")
        # 结束服务
        server.stop()  # 停止服务器


'''
python trusted_party.py 10
'''


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python trusted_party.py <客户端数量>")
        sys.exit(1)

    num_clients = int(sys.argv[1])
    trusted_party = TrustedParty(num_clients)
    trusted_party.run()