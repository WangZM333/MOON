from maskshuffle import *

c = initialize_clients(10)

for i in range(10):
    c[i].gen_grad()
    c[i].add_mask(0)

for i in range(10):
    print(c[i].masked_grad)  # 这时grad应该包含生成的梯度
