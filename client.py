import copy
import time
import pickle
import gmpy2
import zerorpc
import numpy as np
import sys
import threading
from ECIES import *
from phe.paillier import *
import random

global Q, PRIME, random_state
Q = gmpy2.next_prime(2 ** 512)  # 大于2^1024的素数
PRIME = gmpy2.next_prime(2 ** 40)
random_state = gmpy2.random_state()

global vectorsize
vectorsize = 50000

class FederatedClient:
    def __init__(self, client_id, trusted_party_ip, num):
        self.client_id = client_id
        self.ip = None
        self.trusted_party_ip = trusted_party_ip
        self.ecies_pk = None
        self.ecies_sk = None
        self.paillier_pk = None
        self.paillier_sk = None
        self.all_clients_info = []  # 存储其他客户端的信息
        self.aggregator = False
        self.leader = False
        self.gradients_list = []
        self.server = None
        self.client = None
        self.seed_vector = []
        self.sum_seed = None
        self.aggregate = False

        # 生成种子有关参数
        self.Q = Q
        self.num = int(num)
        self.PRIME = PRIME
        self.random_state = random_state
        self.seed = gmpy2.mpz_random(self.random_state, int(self.Q / self.num))
        self.test = 1
        self.vectorsize = vectorsize  # 梯度尺寸大小
        # self.agg_node = 0

        self.grad = None
        self.mask = None
        self.mask_vector = None
        self.masked_grad = None
        self.run_time = 0
        self.leader_time = 0
        self.agg_time = 0
        self.data_size = 0

    # 生成并量化梯度
    def gen_grad(self):
        gradients = 2 * np.random.random(self.vectorsize) - 1
        self.gradients = gradients
        scale_factor = 1e7  # 缩放因子
        scaled_gradients = gradients * scale_factor  # 将浮点数放大
        self.grad = scaled_gradients.astype(np.int32)  # 转换为32位整数

    # 还原量化梯度
    def restore_grad(self, grad):
        scale_factor = 1e7  # 使用相同的缩放因子
        restored_gradients = grad.astype(np.float32) / scale_factor  # 将整数还原为浮点数
        self.restored_gradients = restored_gradients

    # 添加掩码
    def add_mask(self, round):
        # 创建随机数生成器对象，并使用种子初始化
        st = time.time()
        rng = np.random.default_rng(round)
        low, high = -1e7, 1e7
        self.mask_vector = rng.integers(low, high, size=vectorsize)
        self.mask = self.mask_vector * int(self.seed)
        self.masked_grad = self.mask + self.grad
        et = time.time()
        mask_time = et - st
        self.mask_time = mask_time
        # self.masked_grad = pickle.dumps(self.masked_grad)

    def request_client_info(self):
        try:
            client = zerorpc.Client()
            client.connect(f"tcp://{self.trusted_party_ip}:4241")

            # 获取自己的信息（包括公私钥和其他客户端信息）
            client_info = client.get_client_info(self.client_id)
            self_info = pickle.loads(client_info["self_info"])
            self.ip = self_info["ip_address"]
            self.ecies_pk = self_info["public_key"]
            self.ecies_sk = self_info["private_key"]
            self.paillier_pk = self_info["paillier_pk"]
            self.paillier_sk = self_info["paillier_sk"]
            self.all_clients_info = pickle.loads(client_info["all_clients_info"])
            print(self_info)
            print(self.all_clients_info)
            client.close()
            print("初始化完成，连接已关闭")
        except Exception as e:
            print(f"初始化失败: {e}")

    def start_server(self):
        self.server = zerorpc.Server(self)
        self.server.bind(f"tcp://0.0.0.0:{8241 + int(self.client_id)}")
        self.server.run()

    def start_client(self, target_id):
        self.client = zerorpc.Client()
        self.client.connect(f"tcp://127.0.0.1:{8241 + int(target_id)}")

    def receive_message(self, message):
        print(f"客户端 {self.client_id} 收到来自前一个客户端的消息")
        if not self.aggregator:
            self.seed_vector = pickle.loads(message)
        else:
            self.sum_seed = pickle.loads(message)

    def send_to_next_client(self, current_index, message):
        if current_index is not None and current_index < len(self.all_clients_info) - 1:
            next_client_info = self.all_clients_info[current_index + 1]
            target_client_id = next_client_info["client_id"]
            self.send_vector(target_client_id, message)

    def send_vector(self, target_client_id, message):
        self.start_client(target_client_id)
        print(f"客户端{self.client_id}向端口{8241 + int(target_client_id)}发送种子向量")
        self.client.receive_message(message)

    def send_grad(self, target_client_id):
        self.start_client(target_client_id)
        print(f"客户端{self.client_id}向客户端{target_client_id}端口{8241 + int(target_client_id)}发送梯度")
        self.client.receive_grad(self.client_id, pickle.dumps(self.masked_grad))
        print("梯度已发送")

    def receive_grad(self, client_id, grad):
        # 接收到客户端发送的梯度
        # with self.lock:
        print(f"收到来自客户端 {client_id} 的梯度数据")
        self.gradients_list.append(np.array(pickle.loads(grad)))

        if len(self.gradients_list) == len(self.all_clients_info)-1:
            # 如果接收到了所有其他客户端的梯度，进行聚合
            self.gradients_list.append(self.masked_grad)
            self.aggregate_and_broadcast()

        return "梯度已接收"

    def aggregate_and_broadcast(self):
        # 将自己的梯度和接收到的所有梯度相加
        print("开始聚合梯度数据...")
        sum_gradient = np.sum(self.gradients_list, axis=0)
        print("聚合完成，准备将结果发送给所有客户端")

        # 将聚合后的梯度广播给所有客户端
        for client in self.all_clients_info:
            if self.client_id != client['client_id']:
                client_id = client['client_id']
                try:
                    self.start_client(client_id)
                    self.client.receive_aggregate(pickle.dumps(sum_gradient))
                    print(f"已将聚合梯度发送给客户端 {client_id}")
                except Exception as e:
                    print(f"发送给客户端 {client_id} 失败: {e}")
            else:
                self.grad = sum_gradient
                self.aggregate = True


    def receive_aggregate(self, aggregated_grad):
        # 接收聚合梯度
        self.grad = pickle.loads(aggregated_grad)
        self.aggregate = True

    def run(self):
        self.request_client_info()
        print('初始化完成，启动监听服务')
        listening_thread = threading.Thread(target=self.start_server)
        listening_thread.start()
        if self.client_id == self.all_clients_info[-1]["client_id"]:
            print(f"客户端 {self.client_id} 被选为聚合节点，等待接收梯度...")
            self.aggregator = True
        if self.client_id == self.all_clients_info[-2]["client_id"]:
            print(f"客户端 {self.client_id} 被选为leader，等待接收梯度...")
            self.leader = True
        '''
        mask shuffle
        '''
        # 查找在 all_clients_info 中位于自己后面的客户端
        current_index = next((index for index, info in enumerate(self.all_clients_info) if info["client_id"] == self.client_id), None)
        if not self.aggregator and not self.leader:
            paillier_pk = self.all_clients_info[-1]["paillier_pk"]
            encrypted_number = paillier_pk.raw_encrypt(int(self.seed))
            ciphertext = Message(encrypted_number)
            # 倒序遍历位于自己后面的客户端
            for client_info in reversed(self.all_clients_info[current_index + 1:-1]):
                print(f"客户端{self.client_id}找到后面的客户端: {client_info['client_id']}, 公钥{client_info['public_key']}")
                ciphertext.encrypt(client_info["public_key"])

            if self.client_id != self.all_clients_info[0]["client_id"]:
                while not self.seed_vector:
                    time.sleep(0.1)
                print(f"seed vector{self.seed_vector}")
                # 对向量中每个元素进行解密
                for i in range(len(self.seed_vector)):
                    self.seed_vector[i].decrypt(self.ecies_sk)
            self.seed_vector.append(ciphertext)
            random.shuffle(self.seed_vector)
            message = pickle.dumps(self.seed_vector)
            st1 = time.time()
            self.send_vector(self.all_clients_info[current_index + 1]["client_id"], message)
            et1 = time.time()
            t1 = et1 - st1
            print(f"客户端{self.client_id}发送种子密文耗时{t1*1000}ms, 数据大小{len(message)/1024} KB")
        elif self.leader:
            paillier_pk = self.all_clients_info[-1]["paillier_pk"]
            encrypted_number = paillier_pk.raw_encrypt(int(self.seed))
            while not self.seed_vector:
                time.sleep(0.1)
            # 对向量中每个元素进行解密
            for i in range(len(self.seed_vector)):
                self.seed_vector[i].decrypt(self.ecies_sk)
                self.seed_vector[i] = int(Padding.removePadding(self.seed_vector[i].text.decode(), mode=0))
            for i in range(len(self.seed_vector)):
                encrypted_number *= self.seed_vector[i]
            ciphertext = Message(encrypted_number)
            ciphertext.encrypt(self.all_clients_info[current_index+1]["public_key"])
            message = pickle.dumps(ciphertext)
            st1 = time.time()
            self.send_vector(self.all_clients_info[current_index+1]["client_id"], message)
            et1 = time.time()
            t1 = et1 - st1
            print(f"客户端{self.client_id}发送种子密文耗时{t1*1000}ms, 数据大小{len(message)/1024} KB")
        elif self.aggregator:
            while not self.sum_seed:
                time.sleep(0.1)
            print(f"收到的聚合种子密文{self.sum_seed}")
            self.sum_seed.decrypt(self.ecies_sk)
            self.sum_seed = int(Padding.removePadding(self.sum_seed.text.decode(), mode=0))
            self.sum_seed = self.paillier_sk.raw_decrypt(self.sum_seed)
            print(f"聚合种子明文{self.sum_seed}")
            self.seed = -self.sum_seed
            print(f"得到的新种子{self.seed}")

        print(f"mask shuffling 完成，种子为{self.seed}")
        # 生成梯度
        self.gen_grad()
        print(f"本轮梯度{self.grad}")
        # 添加掩码
        self.add_mask(0)

        # 生成同态哈希值

        # 判断是否是最后一个客户端
        if not self.aggregator:
            time.sleep(1)
            last_client_id = self.all_clients_info[-1]["client_id"]
            st2 = time.time()
            self.send_grad(last_client_id)
            et2 = time.time()
            t2 = et2 - st2
            print(f"客户端{self.client_id}发送梯度数据耗时{t2*1000}ms, 数据大小{len(pickle.dumps(self.masked_grad))/1024} KB")
        else:
            print('聚合节点接收并聚合梯度中...')
        while not self.aggregate:
            time.sleep(0.1)
        print('聚合完成')
        print(f"聚合梯度{self.grad}")


'''
python client.py 10 127.0.0.1 1
'''

def main():
    if len(sys.argv) != 4:
        print("用法: python client.py <客户端数量> <可信第三方IP> <客户端ID>")
        sys.exit(1)

    num = sys.argv[1]
    trusted_party_ip = sys.argv[2]
    client_id = sys.argv[3]
    client = FederatedClient(client_id, trusted_party_ip, num)
    client.run()

if __name__ == "__main__":
    main()
