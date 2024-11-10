import time
from maskshuffle import *
import pickle


def main():
    # 客户端初始化
    num_clients = 10
    clients = initialize_clients(num_clients)
    client_ids = []
    grads = []

    sum_grad = np.zeros(vectorsize, dtype=np.object_)
    val_grad = np.zeros(vectorsize, dtype=np.object_)
    for i in range(num_clients):
        client_ids.append(clients[i].id)
        clients[i].gen_grad()
        grads.append(clients[i].grad)

    groups = assign_groups(clients, client_ids)

    start_time = time.time()
    # 第一次mask_shuffle
    # print('-'*100)
    # print('first mask shuffle')
    leader_list = []
    for group in groups:
        leader_list.append(group[-1])
        seed_vector = []
        for client in group[:-1]:
            st1 = time.time()

            current_index = group.index(client)
            clients_after = group[current_index + 1:-1]

            # 加密自己的种子
            encrypted_number = group[-1].paillier_pk.raw_encrypt(int(client.seed))
            ciphertext = Message(encrypted_number)

            # 逐层加密
            for client_after in reversed(clients_after):
                ciphertext.encrypt(client_after.ecies_pk)

            if client != group[0]:
                # 对向量中每个元素进行解密
                # seed_vector = pickle.loads(seed_vector)  # 反序列化
                for i in range(len(seed_vector)):
                    seed_vector[i].decrypt(client.ecies_sk)

                if client == group[-2]:
                    for i in range(len(seed_vector)):  # 只有最后一次解密需要解码
                        seed_vector[i] = int(Padding.removePadding(seed_vector[i].text.decode(), mode=0))

            if client != group[-2]:
                seed_vector.append(ciphertext)
                shuffle_vector(seed_vector)
                # seed_vector = pickle.dumps(seed_vector)
                # # 获取序列化数据的大小
                # size = len(seed_vector)/(1024*1024)
                # client.data_size += size
                # print(f"seed_vector len: {size} MB")
            else:
                seed_vector.append(encrypted_number)
                sum_seed = seed_vector[0]
                for i in range(1, len(seed_vector)):
                    sum_seed *= seed_vector[i]

            et1 = time.time()
            t1 = et1 - st1
            client.maskshuffle_time += t1
        group[-1].sec_seed = int(group[-1].paillier_sk.raw_decrypt(sum_seed)) + group[-1].seed

    # 第二次mask_shuffle
    # print('-'*100)
    # print('second mask shuffle')
    seed_vector = []
    for leader in leader_list[:-1]:
        st2 = time.time()

        current_index = leader_list.index(leader)
        leaders_after = leader_list[current_index + 1:-1]

        encrypted_number = leader_list[-1].paillier_pk.raw_encrypt(int(leader.sec_seed))
        ciphertext = Message(encrypted_number)
        # ciphertext = Message(leader.sec_seed)
        # 逐层加密
        for leader_after in reversed(leaders_after):
            ciphertext.encrypt(leader_after.ecies_pk)

        if leader != leader_list[0]:
            # 对向量中每个元素进行解密
            # seed_vector = pickle.loads(seed_vector)  # 反序列化
            if leader != leader_list[-2]:
                for i in range(len(seed_vector)):
                    seed_vector[i].decrypt(leader.ecies_sk)
            else:
                for i in range(len(seed_vector)):  # 只有最后一次解密需要解码
                    seed_vector[i].decrypt(leader.ecies_sk)
                    seed_vector[i] = int(Padding.removePadding(seed_vector[i].text.decode(), mode=0))

        if leader != leader_list[-2]:
            seed_vector.append(ciphertext)
            shuffle_vector(seed_vector)
            # seed_vector = pickle.dumps(seed_vector)
            # # 获取序列化数据的大小
            # size = len(seed_vector)/(1024*1024)
            # leader.data_size += size
            # print(f"seed_vector len: {size} KB")
        else:
            seed_vector.append(encrypted_number)
            sum_seed = seed_vector[0]
            for i in range(1, len(seed_vector)):
                sum_seed *= seed_vector[i]

        et2 = time.time()
        t2 = et2 - st2
        leader.maskshuffle_time += t2

    leader_list[-1].seed = leader_list[-1].seed - leader_list[-1].sec_seed - int(leader_list[-1].paillier_sk.raw_decrypt(sum_seed))

    # 添加掩码
    for client in clients:
        m_st = time.time()
        client.add_mask(0)
        m_et = time.time()
        client.mask_time = m_et - m_st

    # 生成梯度签名
    for client in clients:
        h_st = time.time()
        client.homohash = homo_hash(np.sum(client.grad), vectorsize)
        # print(client.homohash)
        h_et = time.time()
        client.hash_time = h_et - h_st

    # 梯度聚合
    ag_st = time.time()
    total_data = 0
    for client in clients:
        # client.data_size += (len(client.masked_grad) / (1024 * 1024))
        # client.masked_grad = pickle.loads(client.masked_grad)
        sum_grad += client.masked_grad
    # sum_grad -= (int(clients[-1].paillier_sk.raw_decrypt(sum_seed)) * clients[-1].mask_vector)
    # clients[-1].agg_grad = pickle.dumps(sum_grad)

    ag_et = time.time()
    agg_time = ag_et - ag_st
    clients[-1].agg_grad_time += agg_time

    # 聚合梯度哈希
    ag_h_st = time.time()
    agg_hash = 1
    for client in clients:
        agg_hash = (agg_hash * client.homohash) % PRIME
    # agg_hash = agg_hash % PRIME
    ag_h_et = time.time()
    ag_h_t = ag_h_et - ag_h_st

    # 聚合梯度验证
    v_st = time.time()
    new_hash = homo_hash(np.sum(sum_grad), vectorsize)
    if new_hash == agg_hash:
        print('验证通过')
    else:
        print('验证失败')
        print(f"聚合哈希值{agg_hash}, 聚合梯度哈希值{new_hash}")
    v_et = time.time()
    vt = v_et - v_st

    end_time = time.time()
    total_time = end_time - start_time

    for client in clients:
        val_grad += client.grad

    avg_mask_time = 0
    for client in clients:
        # print(f"client{client.id}'s mask time: {client.mask_time}")
        avg_mask_time += client.mask_time
    avg_mask_time /= num_clients

    avg_hash_time = 0
    for client in clients:
        avg_hash_time += client.hash_time
    avg_hash_time /= num_clients

    avg_maskshuffle_time = 0
    for client in clients[:-2]:
        avg_maskshuffle_time += client.maskshuffle_time
    avg_maskshuffle_time += clients[-2].leader_time
    avg_maskshuffle_time /= (num_clients - 1)

    # avg_data = total_data / num_clients
    # print(f"total data size is: {total_data} MB")
    # print(f"average data size is: {avg_data} MB")
    print(f"average mask shuffle time: {avg_maskshuffle_time * 1000} ms")
    # print((f"leader aggregate seed time: {clients[-2].leader_time*1000} ms"))
    print(f"average add mask time: {avg_mask_time * 1000} ms")
    print(f"average hash time: {avg_hash_time * 1000} ms")

    print(f'aggregation time: {agg_time * 1000} ms')
    print(f"aggregate hash time: {ag_h_t}")
    print(f"verification time: {vt * 1000}ms")
    print('if success:', sum_grad == val_grad)
    print('sum grad: ', sum_grad)
    print('val grad: ', val_grad)


if __name__ == "__main__":
    main()









