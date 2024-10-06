import copy
import socket
import time
import gmpy2
from phe.paillier import *
import random
import numpy as np
from ECIES import *
import time
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import math


global Q, PRIME, random_state
Q = gmpy2.next_prime(2 ** 512)  # 大于2^1024的素数
PRIME = gmpy2.next_prime(2 ** 40)
random_state = gmpy2.random_state()

global vectorsize
vectorsize = 166337

class Client:
    def __init__(self, id, num):
        self.id = id
        # self.host = socket.gethostname()
        # self.port = int("1" + id.zfill(4))

        self.pub_key_map = []  # 客户端列表
        private_key, public_key = make_keypair()  # 加密种子Paillier密文的密钥
        self.ecies_pk = public_key
        self.ecies_sk = private_key
        paillier_pk, paillier_sk = generate_paillier_keypair(n_length=1024)  # Paillier密钥加密种子
        self.paillier_pk = paillier_pk
        self.paillier_sk = paillier_sk

        # 生成种子有关参数
        self.Q = Q
        self.num = num
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

    def sign_gen(self):
        st = time.time()
        self.sigma = self.ecies_sk * sum(self.masked_grad)
        self.omega = homo_hash(sum(self.masked_grad), vectorsize)
        self.k, self.r = make_keypair()
        timestamp = str(time.time())  # 当前时间戳，转换为字符串
        self.e = int(hashlib.sha256(str(self.r).encode()+str(self.masked_grad).encode()+str(self.sigma).encode() +
                                    # timestamp.encode()).hexdigest(), 16)
                                    str(self.omega).encode()+timestamp.encode()).hexdigest(), 16)
        self.s = (self.k - self.ecies_sk * self.e)
        self.sign = {
            'sigma': self.sigma,
            'omega': self.omega,
            'r': self.r,
            's': self.s,
            't': timestamp
        }
        et = time.time()
        self.sign_time = et - st

    def sign_verify(self, clients):
        st = time.time()
        sum_s = 0
        sum_r = None
        sum_ey = None
        for client in clients:
            e = int(hashlib.sha256(str(client.sign['r']).encode()+str(client.masked_grad).encode() +
                                   # str(client.sign['sigma']).encode() +
                                   str(client.sign['sigma']).encode()+str(client.sign['omega']).encode() +
                                   client.sign['t'].encode()).hexdigest(), 16)
            sum_s += client.sign['s']
            if sum_r is None:
                sum_r = client.sign['r']
                sum_ey = scalar_mult(e, client.ecies_pk)
            else:
                sum_r = point_add(sum_r, client.sign['r'])
                sum_ey = point_add(sum_ey, scalar_mult(e, client.ecies_pk))

        if sum_r != point_add(scalar_mult(sum_s, curve.g), sum_ey):
            raise ValueError("验证失败")

        et = time.time()
        self.sign_verify_time = et - st

    def pro_gen(self, clients, m):
        st = time.time()
        h = {}
        sigma = {}
        omega = {}
        concatenated_h = None
        for client in clients:
            # client.h = scalar_mult((sum(client.masked_grad * self.ecies_sk)), client.ecies_pk)
            client.h = scalar_mult((sum(client.masked_grad) * self.ecies_sk * client.sign['omega']), client.ecies_pk)
            h[client.id] = client.h
            sigma[client.id] = client.sigma
            omega[client.id] = client.omega
            if concatenated_h is None:
                concatenated_h = str(client.h)
            else:
                concatenated_h = concatenated_h + str(client.h)
        z, delta = make_keypair()
        h_m = homo_hash(sum(m), vectorsize)
        timestamp = str(time.time())  # 当前时间戳，转换为字符串
        # eta = int(hashlib.sha256(str(delta).encode()+str(m).encode()+str(concatenated_h).encode() +
        eta = int(hashlib.sha256(str(delta).encode()+str(m).encode()+str(concatenated_h).encode()+str(h_m).encode() +
                                 timestamp.encode()).hexdigest(), 16)
        l = (z - self.ecies_sk * eta)
        pro = {
            'm': m,
            'h': h,
            'sigma': sigma,
            'omega': omega,
            'delta': delta,
            'l': l,
            'eta': eta,
            't': timestamp
        }

        et = time.time()
        self.pro_gen_time = et - st

        return pro


    def verify(self, mu, pro):
        st = time.time()

        sum_h_sigma = None
        h_m = homo_hash(sum(pro['m']), vectorsize)
        if pro['delta'] != point_add(scalar_mult(pro['l'], curve.g), scalar_mult(pro['eta'], mu)):
            raise ValueError("验证失败")
        # if pro['h'][self.id] != scalar_mult(self.sigma, mu):
        if pro['h'][self.id] != scalar_mult((self.sigma * self.omega), mu):
            raise ValueError("验证失败")
        for id, h in pro['h'].items():
            if sum_h_sigma is None:
                # sum_h_sigma = scalar_mult(pro['omega'][id], mu)
                sum_h_sigma = scalar_mult(point_neg(pro['sigma'][id]), h)
                # sum_h_sigma = scalar_mult((1/pro['sigma'][id]), h)
            else:
                # sum_h_sigma = point_add(sum_h_sigma, scalar_mult(pro['omega'][id], mu))
                sum_h_sigma = point_add(sum_h_sigma, scalar_mult(point_neg(pro['sigma'][id]), h))
                # sum_h_sigma = point_add(sum_h_sigma, scalar_mult((1/pro['sigma'][id]), h))
        # if sum_h_sigma != mu:
        if sum_h_sigma != scalar_mult(h_m, mu):
            raise ValueError("验证失败")

        et = time.time()
        self.verify_time = et - st


def homo_hash(value, key):  # x:输入同态哈希函数的值， k:同台哈希函数的密钥
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.to_bytes(24, 'big'))
    hx = digest.finalize()
    hx_int = int.from_bytes(hx, "big")
    ru = gmpy2.powmod(gmpy2.mpz(hx_int), gmpy2.mpz(value), PRIME)

    return ru

def initialize_clients(num_clients):
    clients = []
    for i in range(num_clients):
        clients.append(Client(id=i, num=num_clients))
    return clients


def shuffle_vector(vector):
    random.shuffle(vector)
    return vector


def assign_groups(clients, client_ids):
    n = len(clients)
    group_num = int(math.sqrt(n))
    groups = []  # 初始化每组的列表

    remaining_ids = copy.deepcopy(client_ids)
    random.shuffle(remaining_ids)

    for i in range(group_num):
        groups.append([])
        sampled_ids = random.sample(remaining_ids, group_num)
        for j in sampled_ids:
            groups[i].append(clients[j])

        remaining_ids = [id for id in remaining_ids if id not in sampled_ids]
    for i, id in enumerate(remaining_ids):
        groups[i%group_num].append(clients[id])

    return groups

def mask_shuffle(clients, num_clients):
    # 密钥初始化
    paillier_pub, paillier_priv = generate_paillier_keypair(n_length=1024)
    private_keys, public_keys = generate_keys(clients)
    confuse_client = clients[:-1]
    masks = []
    mask_vector = []

    for client in confuse_client:
        seed = gmpy2.mpz_random(random_state, int(Q/len(num_clients)))  # 生成自己的种子
        masks.append(seed)

        # 获取当前 client 之后的客户端列表
        current_index = confuse_client.index(client)
        clients_after = confuse_client[current_index + 1:]

        # 加密自己的种子
        encrypted_number = paillier_pub.raw_encrypt(int(seed))
        ciphertext = Message(encrypted_number)

        # 逐层加密
        for client_after in reversed(clients_after):
            ciphertext.encrypt(public_keys[client_after])

        if client != confuse_client[0]:
            # 对向量中每个元素进行解密
            for i in range(len(mask_vector)):
                mask_vector[i].decrypt(private_keys[client])

            if client == confuse_client[-1]:
                for i in range(len(mask_vector)):  # 只有最后一次解密需要解码
                    mask_vector[i] = int(Padding.removePadding(mask_vector[i].text.decode(), mode=0))

        if client != confuse_client[-1]:
            mask_vector.append(ciphertext)
        else:
            mask_vector.append(encrypted_number)

        shuffle_vector(mask_vector)
        if client == confuse_client[-1]:
            result = mask_vector[0]
            for i in range(1, len(mask_vector)):
                result *= mask_vector[i]

    dec_result = paillier_priv.raw_decrypt(result)
    masks.append((-dec_result))

    return masks


def main():
    # 客户端初始化
    num_clients = 2
    clients = initialize_clients(num_clients)
    client_ids = []
    grads = []

    sum_grad = np.zeros(vectorsize, dtype=np.object_)
    val_grad = np.zeros(vectorsize, dtype=np.object_)
    for i in range(num_clients):
        client_ids.append(clients[i].id)
        clients[i].gen_grad()
        grads.append(clients[i].grad)

    seed_vector = []
    start_time = time.time()
    for client in clients:
        st1 = time.time()
        # 获取当前 client 之后的客户端列表
        current_index = clients.index(client)
        clients_after = clients[current_index + 1:]

        # 加密自己的种子
        # paillier_start_time = time.time()
        encrypted_number = clients[-1].paillier_pk.raw_encrypt(int(client.seed))
        # paillier_end_time = time.time()
        # paillier_time = paillier_end_time - paillier_start_time
        # print('paillier time: ', paillier_time)
        ciphertext = Message(encrypted_number)
        # 逐层加密
        # enc_start_time = time.time()
        for client_after in reversed(clients_after):
            ciphertext.encrypt(client_after.ecies_pk)
        # enc_end_time = time.time()
        # enc_time = enc_end_time - enc_start_time
        # print('enc time:', enc_time)

        if client != clients[0]:
            # 对向量中每个元素进行解密
            # seed_vector = pickle.loads(seed_vector)
            for i in range(len(seed_vector)):
                seed_vector[i].decrypt(client.ecies_sk)

            if client == clients[-1]:
                for i in range(len(seed_vector)):  # 只有最后一次解密需要解码
                    seed_vector[i] = int(Padding.removePadding(seed_vector[i].text.decode(), mode=0))

        if client != clients[-1]:
            seed_vector.append(ciphertext)
            shuffle_vector(seed_vector)
            # seed_vector = pickle.dumps(seed_vector)
            # # 获取序列化数据的大小
            # size = len(seed_vector) / (1024 * 1024)
            # client.data_size += size
            # print(f"seed_vector len: {size} MB")
        else:
            seed_vector.append(encrypted_number)
            sum_seed = seed_vector[0]
            for i in range(1, len(seed_vector)):
                sum_seed *= seed_vector[i]

        et1 = time.time()
        t1 = et1 - st1
        client.run_time += t1

    # 添加掩码
    m_st = time.time()
    for client in clients:
        client.add_mask(0)
    m_et = time.time()
    mask_time = m_et - m_st

    # # 生成签名
    # for client in clients:
    #     client.sign_gen()
    #
    # # 验证签名
    # clients[-1].sign_verify(clients)

    # 梯度聚合
    ag_st = time.time()
    total_data = 0
    for client in clients:
        # client.data_size += (len(client.masked_grad) / (1024 * 1024))
        # client.masked_grad = pickle.loads(client.masked_grad)
        sum_grad += client.masked_grad
    sum_grad -= (int(clients[-1].paillier_sk.raw_decrypt(sum_seed)) * clients[-1].mask_vector)
    # clients[-1].agg_grad = pickle.dumps(sum_grad)

    ag_et = time.time()
    agg_time = ag_et - ag_st
    clients[-1].leader_time += agg_time


    # TODO:聚合梯度验证


    end_time = time.time()
    total_time = end_time - start_time

    for client in clients:
        val_grad += client.grad

    avg_mask_time = 0
    for client in clients:
        # print(f"client{client.id}'s mask time: {client.mask_time}")
        avg_mask_time += client.mask_time
    avg_mask_time /= num_clients

    avg_run_time = 0
    leader_time = 0
    for client in clients:
        if client.leader_time == 0:
            # print(f"client{client.id}'s run time: {client.run_time}")
            avg_run_time += (client.run_time + client.mask_time)
        else:
            leader_time += (client.leader_time + client.run_time + client.mask_time)
            # print(f'client{client.id} is leader, its run time is: {client.leader_time*1000}')
    avg_run_time /= (num_clients-1)

    # avg_data = total_data / num_clients
    # print(f"total data size is: {total_data} MB")
    # print(f"average data size is: {avg_data} MB")
    print('leader run time: ', leader_time*1000)
    print('run time per client: ', avg_run_time*1000)
    print('aggregation time: ', agg_time*1000)

    print('total mask time: ', mask_time)
    print('total time: ', total_time)
    print('if success:', sum_grad == val_grad)
    print('sum grad: ', sum_grad)
    print('val grad: ', val_grad)



if __name__ == "__main__":
    main()



