import copy
import signal
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import yaml
import argparse
import subprocess
import logging
import os


class FederatedClient:
    def __init__(self, client_id, trusted_party_ip, num, alg):
        self.client_id = client_id
        self.ip = None
        self.trusted_party_ip = trusted_party_ip
        self.ecies_pk = None
        self.ecies_sk = None
        self.paillier_pk = None
        self.paillier_sk = None
        self.all_clients_info = []  # 存储其他客户端的信息
        self.group_info = None
        self.sec_shuffle = None

        self.seed_vector = []
        self.sec_vector = []
        self.sum_seed = None
        self.total_sum_seed = None
        self.sec_seed = None

        self.gradients_list = []
        self.grad_server = None
        self.seed_server = None
        self.server = None
        self.grad_client = None
        self.seed_client = None
        self.client = None

        self.hash_list = []

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
        self.running = True  # 线程运行标志

        self.group_flag = False
        if int(alg) == 1:
            self.group_flag = True

        self.aggregate = False
        self.group_sum_holder = False
        self.total_sum_holder = False
        self.sec_round = False
        self.aggregator = False
        self.leader = False

    # 生成并量化梯度
    def gen_grad(self):
        gradients = np.round(np.random.random(self.vectorsize) * 2 - 1, 4)
        self.gradients = gradients
        scale_factor = 1e4  # 缩放因子
        scaled_gradients = gradients * scale_factor  # 将浮点数放大
        self.grad = scaled_gradients.astype(np.int32)  # 转换为32位整数


    # 还原量化梯度
    def restore_grad(self, grad):
        scale_factor = 1e4  # 使用相同的缩放因子
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
            client = zerorpc.Client(timeout=None, heartbeat=None)
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
            self.group_info = pickle.loads(client_info['group_info'])
            self.sec_shuffle = pickle.loads(client_info['sec_shuffle_info'])
            client.close()
            print("初始化完成，连接已关闭")
        except Exception as e:
            print(f"初始化失败: {e}")
            pid = os.getpid()  # 获取当前进程的PID
            os.kill(pid, signal.SIGTERM)  # 主动结束指定ID的程序运行


    def start_server(self):
        self.server = zerorpc.Server(self)
        self.server.bind(f"tcp://0.0.0.0:{8241 + int(self.client_id)}")
        self.server.run()

    def start_client(self, target_id):
        self.client = zerorpc.Client(timeout=None, heartbeat=3000)
        self.client.connect(f"tcp://127.0.0.1:{8241 + int(target_id)}")

    def receive_message(self, message):
        logging.info(f"客户端 {self.client_id} 收到来自前一个客户端的消息")
        if not self.sec_round:
            if self.group_sum_holder:
                self.sum_seed = pickle.loads(message)
            elif self.total_sum_holder:
                self.sum_seed = pickle.loads(message)
            else:
                self.seed_vector = pickle.loads(message)
        else:
            if self.total_sum_holder:
                self.total_sum_seed = pickle.loads(message)
            else:
                self.sec_vector = pickle.loads(message)

    def send_vector(self, target_client_id, message):
        self.start_client(target_client_id)
        logging.info(f"客户端{self.client_id}向客户端{target_client_id}发送种子向量")
        self.client.receive_message(message)

    def send_grad(self, target_client_id):
        self.start_client(target_client_id)
        logging.info(f"客户端{self.client_id}向客户端{target_client_id}发送梯度")
        self.client.receive_grad(self.client_id, pickle.dumps((self.masked_grad, self.hash_value)))
        print("梯度已发送")


    def receive_grad(self, client_id, message):
        # 接收到客户端发送的梯度
        # with self.lock:
        logging.info(f"收到来自客户端 {client_id} 的梯度数据")
        message = pickle.loads(message)
        self.gradients_list.append(np.array(message[0]))
        self.hash_list.append(message[1])

        if len(self.gradients_list) == len(self.all_clients_info)-1:
            # 如果接收到了所有其他客户端的梯度，进行聚合
            self.gradients_list.append(self.masked_grad)
            self.aggregate_and_broadcast()

        return "梯度已接收"

    def aggregate_and_broadcast(self):
        # 将自己的梯度和接收到的所有梯度相加
        print("开始聚合梯度数据...")
        agg_hash = 1
        for i in range(len(self.hash_list)):
            agg_hash *= self.hash_list[i]
        agg_hash = agg_hash % PRIME
        print(f"hash list{self.hash_list}")
        self.agg_hash = agg_hash
        st3 = time.time()
        sum_gradient = np.sum(self.gradients_list, axis=0)
        et3 = time.time()
        t3 = et3 - st3
        logging.info(f"聚合节点聚合梯度数据耗时{t3 * 1000}ms")

        print("聚合完成，准备将结果发送给所有客户端")

        # 将聚合后的梯度广播给所有客户端
        for client in self.all_clients_info:
            if self.client_id != client['client_id']:
                client_id = client['client_id']
                try:
                    self.start_client(client_id)
                    self.client.receive_aggregate(pickle.dumps((sum_gradient, agg_hash)))
                    logging.info(f"已将聚合梯度发送给客户端 {client_id}")
                except Exception as e:
                    logging.info(f"发送给客户端 {client_id} 失败: {e}")
            else:
                self.grad = sum_gradient
                self.aggregate = True


    def receive_aggregate(self, aggregated_grad):
        # 接收聚合梯度
        aggregated_grad = pickle.loads(aggregated_grad)
        self.grad = aggregated_grad[0]
        self.agg_hash = aggregated_grad[1]
        self.aggregate = True


    def layer_encrypt(self, client_info, current_index, ciphertext):
        # 倒序遍历位于自己后面的客户端
        for client_info in reversed(client_info[current_index + 1:-1]):
            logging.info(f"客户端{self.client_id}找到后面的客户端: {client_info['client_id']}, 公钥{client_info['public_key']}")
            ciphertext.encrypt(client_info["public_key"])

    def decrypt_seed_vector(self):
        for i in range(len(self.seed_vector)):
            self.seed_vector[i].decrypt(self.ecies_sk)
            if self.leader:
                self.seed_vector[i] = int(Padding.removePadding(self.seed_vector[i].text.decode(), mode=0))
        # return seed_vector

    def mask_shuffle(self):
        if self.client_id == self.all_clients_info[-2]["client_id"]:
            logging.info(f"客户端 {self.client_id} 被选为leader")
            self.leader = True
        elif self.client_id == self.all_clients_info[-1]["client_id"]:
            logging.info(f"客户端 {self.client_id} 持有种子总和")
            self.total_sum_holder = True
        # 查找在 all_clients_info 中位于自己后面的客户端
        current_index = next((index for index, info in enumerate(self.all_clients_info) if info["client_id"] == self.client_id), None)
        if not self.total_sum_holder and not self.leader:
            paillier_pk = self.all_clients_info[-1]["paillier_pk"]
            encrypted_number = paillier_pk.raw_encrypt(int(self.seed))
            ciphertext = Message(encrypted_number)

            self.layer_encrypt(self.all_clients_info, current_index, ciphertext)

            if self.client_id != self.all_clients_info[0]["client_id"]:
                while not self.seed_vector:
                    time.sleep(0.005)
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
            logging.info(f"客户端{self.client_id}发送种子密文耗时{t1 * 1000}ms, 数据大小{len(message) / 1024} KB")
        elif self.leader:
            paillier_pk = self.all_clients_info[-1]["paillier_pk"]
            encrypted_number = paillier_pk.raw_encrypt(int(self.seed))
            while not self.seed_vector:
                time.sleep(0.005)
            # 对向量中每个元素进行解密
            for i in range(len(self.seed_vector)):
                self.seed_vector[i].decrypt(self.ecies_sk)
                self.seed_vector[i] = int(Padding.removePadding(self.seed_vector[i].text.decode(), mode=0))
            for i in range(len(self.seed_vector)):
                encrypted_number *= self.seed_vector[i]
            ciphertext = Message(encrypted_number)
            ciphertext.encrypt(self.all_clients_info[current_index + 1]["public_key"])
            message = pickle.dumps(ciphertext)
            st1 = time.time()
            self.send_vector(self.all_clients_info[current_index + 1]["client_id"], message)
            et1 = time.time()
            t1 = et1 - st1
            logging.info(f"客户端{self.client_id}发送种子密文耗时{t1 * 1000}ms, 数据大小{len(message) / 1024} KB")
        elif self.total_sum_holder:
            while not self.sum_seed:
                time.sleep(0.005)
            logging.info(f"收到的聚合种子密文{self.sum_seed}")
            self.sum_seed.decrypt(self.ecies_sk)
            self.sum_seed = int(Padding.removePadding(self.sum_seed.text.decode(), mode=0))
            self.sum_seed = self.paillier_sk.raw_decrypt(self.sum_seed)
            logging.info(f"聚合种子明文{self.sum_seed}")
            self.seed = -self.sum_seed
            logging.info(f"得到的新种子{self.seed}")

        logging.info(f"mask shuffling 完成，种子为{self.seed}")

    def group_shuffle(self):
        if self.client_id == self.group_info[-2]["client_id"]:
            logging.info(f"客户端 {self.client_id} 被选为第一轮leader")
            self.leader = True
        elif self.client_id == self.group_info[-1]["client_id"]:
            logging.info(f"客户端 {self.client_id} 会进行第二轮mask shuffle")
            self.group_sum_holder = True
        # 查找位于自己后面的客户端
        current_index = next((index for index, info in enumerate(self.group_info) if info["client_id"] == self.client_id), None)
        if not self.group_sum_holder and not self.leader:
            paillier_pk = self.group_info[-1]["paillier_pk"]
            encrypted_number = paillier_pk.raw_encrypt(int(self.seed))
            ciphertext = Message(encrypted_number)

            self.layer_encrypt(self.group_info, current_index, ciphertext)

            if self.client_id != self.group_info[0]["client_id"]:
                while not self.seed_vector:
                    time.sleep(0.005)
                print(f"seed vector{self.seed_vector}")
                # 对向量中每个元素进行解密
                for i in range(len(self.seed_vector)):
                    self.seed_vector[i].decrypt(self.ecies_sk)
            self.seed_vector.append(ciphertext)
            random.shuffle(self.seed_vector)
            message = pickle.dumps(self.seed_vector)
            st1 = time.time()
            self.send_vector(self.group_info[current_index + 1]["client_id"], message)
            et1 = time.time()
            t1 = et1 - st1
            logging.info(f"客户端{self.client_id}发送种子密文耗时{t1 * 1000}ms, 数据大小{len(message) / 1024} KB")
        elif self.leader:
            paillier_pk = self.group_info[-1]["paillier_pk"]
            encrypted_number = paillier_pk.raw_encrypt(int(self.seed))
            while not self.seed_vector:
                time.sleep(0.005)
            logging.info(f"收到的种子向量： {self.seed_vector}")
            # 对向量中每个元素进行解密
            for i in range(len(self.seed_vector)):
                self.seed_vector[i].decrypt(self.ecies_sk)
                self.seed_vector[i] = int(Padding.removePadding(self.seed_vector[i].text.decode(), mode=0))
            for i in range(len(self.seed_vector)):
                encrypted_number *= self.seed_vector[i]
            ciphertext = Message(encrypted_number)
            ciphertext.encrypt(self.group_info[current_index + 1]["public_key"])
            message = pickle.dumps(ciphertext)
            st1 = time.time()
            self.send_vector(self.group_info[current_index + 1]["client_id"], message)
            et1 = time.time()
            t1 = et1 - st1
            logging.info(f"客户端{self.client_id}发送种子密文耗时{t1 * 1000}ms, 数据大小{len(message) / 1024} KB")
        elif self.group_sum_holder:
            while not self.sum_seed:
                time.sleep(0.005)
            logging.info(f"收到的聚合种子密文{self.sum_seed}")
            self.sum_seed.decrypt(self.ecies_sk)
            self.sum_seed = int(Padding.removePadding(self.sum_seed.text.decode(), mode=0))
            self.sum_seed = self.paillier_sk.raw_decrypt(self.sum_seed)
            logging.info(f"聚合种子明文{self.sum_seed}")
            self.sec_seed = self.sum_seed + self.seed
            logging.info(f"本组种子之和{self.sec_seed}")
            logging.info("第二轮掩码混淆开始")
            self.sec_round = True
            if self.client_id == self.sec_shuffle[-2]["client_id"]:
                logging.info(f"客户端 {self.client_id} 被选为第二轮leader")
                self.leader = True
            elif self.client_id == self.sec_shuffle[-1]["client_id"]:
                logging.info(f"客户端 {self.client_id} 持有种子总和")
                self.total_sum_holder = True
            # 查找位于自己后面的客户端
            current_index = next((index for index, info in enumerate(self.sec_shuffle) if info["client_id"] == self.client_id), None)
            if not self.total_sum_holder and not self.leader:
                paillier_pk = self.sec_shuffle[-1]["paillier_pk"]
                encrypted_number = paillier_pk.raw_encrypt(int(self.sec_seed))
                ciphertext = Message(encrypted_number)
                self.layer_encrypt(self.sec_shuffle, current_index, ciphertext)

                if self.client_id != self.sec_shuffle[0]["client_id"]:
                    while not self.sec_vector:
                        time.sleep(0.005)
                    print(f"second seed vector{self.sec_vector}")
                    # 对向量中每个元素进行解密
                    for i in range(len(self.sec_vector)):
                        self.sec_vector[i].decrypt(self.ecies_sk)
                self.sec_vector.append(ciphertext)
                random.shuffle(self.sec_vector)
                message = pickle.dumps(self.sec_vector)
                st1 = time.time()
                self.send_vector(self.sec_shuffle[current_index + 1]["client_id"], message)
                et1 = time.time()
                t1 = et1 - st1
                logging.info(f"客户端{self.client_id}发送种子密文耗时{t1 * 1000}ms, 数据大小{len(message) / 1024} KB")
            elif self.leader:
                paillier_pk = self.sec_shuffle[-1]["paillier_pk"]
                encrypted_number = paillier_pk.raw_encrypt(int(self.sec_seed))
                while not self.sec_vector:
                    time.sleep(0.005)
                # 对向量中每个元素进行解密
                for i in range(len(self.sec_vector)):
                    self.sec_vector[i].decrypt(self.ecies_sk)
                    self.sec_vector[i] = int(Padding.removePadding(self.sec_vector[i].text.decode(), mode=0))
                for i in range(len(self.sec_vector)):
                    encrypted_number *= self.sec_vector[i]
                ciphertext = Message(encrypted_number)
                ciphertext.encrypt(self.sec_shuffle[current_index + 1]["public_key"])
                message = pickle.dumps(ciphertext)
                st1 = time.time()
                self.send_vector(self.sec_shuffle[current_index + 1]["client_id"], message)
                et1 = time.time()
                t1 = et1 - st1
                logging.info(f"客户端{self.client_id}发送种子密文耗时{t1 * 1000}ms, 数据大小{len(message) / 1024} KB")
            elif self.total_sum_holder:
                while not self.total_sum_seed:
                    time.sleep(0.005)
                logging.info(f"收到的聚合种子密文{self.total_sum_seed}")
                self.total_sum_seed.decrypt(self.ecies_sk)
                self.total_sum_seed = int(Padding.removePadding(self.total_sum_seed.text.decode(), mode=0))
                self.total_sum_seed = self.paillier_sk.raw_decrypt(self.total_sum_seed)
                logging.info(f"聚合种子明文{self.total_sum_seed}")
                self.seed = self.seed - self.sec_seed - self.total_sum_seed
                logging.info(f"得到的新种子{self.seed}")

        logging.info(f"double mask shuffling 完成，种子为{self.seed}")


    def run(self):
        logging.info("*"*50 + "客户端启动" + "*"*50)
        self.request_client_info()
        print('初始化完成，启动监听服务')

        listening_thread = threading.Thread(target=self.start_server)
        listening_thread.start()

        if self.client_id == self.all_clients_info[-1]["client_id"]:
            logging.info(f"客户端 {self.client_id} 被选为聚合节点")
            self.aggregator = True

        if self.group_flag:
            self.group_shuffle()
        else:
            self.mask_shuffle()

        # 生成梯度
        self.gen_grad()
        logging.info(f"本轮梯度{self.grad}")
        # 添加掩码
        self.add_mask(0)
        # 生成同态哈希值
        self.hash_value = homo_hash(sum(self.grad), vectorsize)
        logging.info(f"本地梯度同态哈希值{self.hash_value}")

        # 判断是否是最后一个客户端
        if not self.aggregator:
            time.sleep(1)
            last_client_id = self.all_clients_info[-1]["client_id"]
            st2 = time.time()
            self.send_grad(last_client_id)
            et2 = time.time()
            t2 = et2 - st2
            logging.info(f"客户端{self.client_id}发送梯度数据耗时{t2*1000}ms, 数据大小{len(pickle.dumps(self.masked_grad))/1024} KB")
        else:
            self.hash_list.append(self.hash_value)
            print('聚合节点接收并聚合梯度中...')
        while not self.aggregate:
            time.sleep(0.005)
        h = homo_hash(sum(self.grad), vectorsize)
        print('聚合完成')
        logging.info(f"聚合哈希值{self.agg_hash}")
        logging.info(f"聚合梯度哈希值{h}")
        logging.info(f"聚合梯度{self.grad}")
        logging.info("*" * 50 + "客户端关闭" + "*" * 50)
        pid = os.getpid()  # 获取当前进程的PID
        os.kill(pid, signal.SIGTERM)  # 主动结束指定ID的程序运行

def homo_hash(value, key):  # x:输入同态哈希函数的值， k:同台哈希函数的密钥
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.to_bytes(24, 'big'))
    hx = digest.finalize()
    hx_int = int.from_bytes(hx, "big")
    ru = gmpy2.powmod(gmpy2.mpz(hx_int), gmpy2.mpz(value), PRIME)

    return ru

'''
单轮： python client.py 0 200000 14 127.0.0.1 1
双轮： python client.py 1 200000 11 127.0.0.1 1
'''
'''
group shuffle 在大于10个客户端的情况下有bug
mask shuffle 在客户端数量超过61个之后会卡住，可能是因为接收梯度和种子向量的端口相同导致阻塞
'''
def main():
    if len(sys.argv) != 6:
        print("用法: python client.py <算法> <梯度向量尺寸> <客户端数量> <可信第三方IP> <客户端ID>")
        sys.exit(1)

    global Q, PRIME, random_state
    Q = gmpy2.next_prime(2 ** 32)  # 大于2^512的素数
    PRIME = gmpy2.next_prime(2 ** 80)
    random_state = gmpy2.random_state()

    global vectorsize

    alg = sys.argv[1]
    vectorsize = int(sys.argv[2])
    num = sys.argv[3]
    trusted_party_ip = sys.argv[4]
    client_id = sys.argv[5]

    logging.basicConfig(
        filename=f'mask_shuffle_log/client_{client_id}.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        # encoding='utf-8'
    )

    client = FederatedClient(client_id, trusted_party_ip, num, alg)
    client.run()

if __name__ == "__main__":
    main()
