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
        for client in group:
            st1 = time.time()

            current_index = group.index(client)
            clients_after = group[current_index + 1:]

            # 加密自己的种子
            encrypted_number = groups[-1][-1].paillier_pk.raw_encrypt(int(client.seed))
            ciphertext = Message(encrypted_number)

            # 逐层加密
            for client_after in reversed(clients_after):
                ciphertext.encrypt(client_after.ecies_pk)

            if client != group[0]:
                # 对向量中每个元素进行解密
                # seed_vector = pickle.loads(seed_vector)  # 反序列化
                for i in range(len(seed_vector)):
                    seed_vector[i].decrypt(client.ecies_sk)

                if client == group[-1]:
                    for i in range(len(seed_vector)):  # 只有最后一次解密需要解码
                        seed_vector[i] = int(Padding.removePadding(seed_vector[i].text.decode(), mode=0))

            if client != group[-1]:
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

                group[-1].sec_seed = sum_seed

            et1 = time.time()
            t1 = et1 - st1
            client.run_time += t1

    # 第二次mask_shuffle
    # print('-'*100)
    # print('second mask shuffle')
    seed_vector = []
    for leader in leader_list:
        st2 = time.time()

        current_index = leader_list.index(leader)
        leaders_after = leader_list[current_index + 1:]

        ciphertext = Message(leader.sec_seed)
        # 逐层加密
        for leader_after in reversed(leaders_after):
            ciphertext.encrypt(leader_after.ecies_pk)

        if leader != leader_list[0]:
            # 对向量中每个元素进行解密
            # seed_vector = pickle.loads(seed_vector)  # 反序列化
            if leader != leader_list[-1]:
                for i in range(len(seed_vector)):
                    seed_vector[i].decrypt(leader.ecies_sk)
            else:
                for i in range(len(seed_vector)):  # 只有最后一次解密需要解码
                    seed_vector[i].decrypt(leader.ecies_sk)
                    seed_vector[i] = int(Padding.removePadding(seed_vector[i].text.decode(), mode=0))


        if leader != leader_list[-1]:
            seed_vector.append(ciphertext)
            shuffle_vector(seed_vector)
            # seed_vector = pickle.dumps(seed_vector)
            # # 获取序列化数据的大小
            # size = len(seed_vector)/(1024*1024)
            # leader.data_size += size
            # print(f"seed_vector len: {size} KB")
        else:
            seed_vector.append(leader.sec_seed)
            sum_seed = seed_vector[0]
            for i in range(1, len(seed_vector)):
                sum_seed *= seed_vector[i]


        et2 = time.time()
        t2 = et2 - st2
        leader.leader_time += t2


    # 添加掩码
    m_st = time.time()
    for client in clients:
        client.add_mask(0)
    m_et = time.time()
    mask_time = m_et - m_st

    # 梯度聚合
    # print('-'*100)
    ag_st = time.time()
    total_data = 0
    for client in clients:
        # client.data_size += (len(client.masked_grad)/(1024*1024))
        # client.masked_grad = pickle.loads(client.masked_grad)
        sum_grad += client.masked_grad
    sum_grad -= (int(leader_list[-1].paillier_sk.raw_decrypt(sum_seed)) * leader_list[-1].mask_vector)
    leader_list[-1].agg_grad = pickle.dumps(sum_grad)

    ag_et = time.time()
    agg_time = ag_et - ag_st
    leader_list[-1].leader_time += agg_time

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
    avg_run_time /= (num_clients-len(leader_list))
    leader_time /= len(leader_list)


    # avg_data = total_data/num_clients
    # print(f"total data size is: {total_data} MB")
    # print(f"average data size is: {avg_data} MB")
    print('leader run time: ', leader_time * 1000)
    print('run time per client: ', avg_run_time * 1000)
    # print('average mask time: ', avg_mask_time*1000)
    # print('aggregation time: ', agg_time*1000)

    # print('total mask time: ', mask_time)
    print('total time: ', total_time)
    print('if success:', sum_grad==val_grad)
    print('sum grad: ', sum_grad)
    print('val grad: ', val_grad)


if __name__ == "__main__":
    main()









