
import time
from net_env_multi_actions_full_new_reward import networkEnv
import numpy as np
import argparse
import sys
from scapy.all import *
from scapy.all import Ether, ICMP, IP, TCP, UDP, Raw



RESULTS = "/vagrant/results/"
VERBOSE=False

def run(run_num, netpaxos):
    with networkEnv(4, verbose=VERBOSE, netp=netpaxos) as env:
        env.reward_system.run = run_num
        start = time.time()
        run = 0
        first_reward = False
        first_reward_seen = 0
        first_bug_time = -1
        for i in range(2000):
            random_num = np.random.randint(0,8)
            if random_num == 0:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=6,
                         len=20,
                         id=512,
                         flags=0,
                         frag=0,
                         ttl=64,
                         proto=np.random.randint(0, 255),
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)#TCP(sport=5678, dport=1234)/ TCP(sport=5678, dport=1234)

            elif random_num == 1:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=np.random.randint(0, 15),
                         ihl=5,
                         tos=6,
                         len=20,
                         id=512,
                         flags=0,
                         frag=0,
                         ttl=64,
                         proto=6,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 2:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=np.random.randint(0, 15),
                         tos=6,
                         len=20,
                         id=512,
                         flags=0,
                         frag=0,
                         ttl=64,
                         proto=17,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 3:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=np.random.randint(0, 255),
                         len=20,
                         id=512,
                         flags=0,
                         frag=0,
                         ttl=64,
                         proto=6,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 4:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=6,
                         len=np.random.randint(0, 65535),
                         id=512,
                         flags=0,
                         frag=0,
                         ttl=64,
                         proto=40,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 5:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=6,
                         len=20,
                         id=np.random.randint(0, 65535),
                         flags=0,
                         frag=0,
                         ttl=64,
                         proto=6,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 6:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=6,
                         len=20,
                         id=512,
                         flags=np.random.randint(0, 7),
                         frag=0,
                         ttl=64,
                         proto=6,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 7:
                pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=6,
                         len=20,
                         id=512,
                         flags=0,
                         frag=np.random.randint(0, 8191),
                         ttl=64,
                         proto=56,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

            elif random_num == 8:
              pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
                      IP(version=4,
                         ihl=5,
                         tos=6,
                         len=20,
                         id=512,
                         flags=0,
                         frag=0,
                         ttl=np.random.randint(0,255),
                         proto=6,
                         src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
                         dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)

#            pkt = Ether(src=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))], dst=env.valid_macs_temp[np.random.randint(0, len(env.valid_macs_temp))]) / \
 #                     IP(version=np.random.randint(0, 15),
  #                       ihl=np.random.randint(0, 15),
   #                      tos=np.random.randint(0, 255),
    #                     len=np.random.randint(0, 65535),
     #                    id=np.random.randint(0, 65535),
      #                   flags=np.random.randint(0, 7),
       #                  frag=np.random.randint(0, 8191),
        #                 ttl=np.random.randint(0,255),
         #                proto=np.random.randint(0, 255),
          #               src=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))],
           #              dst=env.valid_dst_ips_temp[np.random.randint(0, len(env.valid_dst_ips_temp))]) / np.random.bytes(40)#TCP(sport=5678, dport=1234)/ TCP(sport=5678, dport=1234)
            run += 1
            env.x = bytearray(bytes(pkt))
            reward = env.check_reward()
            if reward==1 and not first_reward:
                first_reward = True
                first_reward_seen = run
                first_bug_time = time.time() - start
                break
        print("loop finished")
        end = time.time()
        execution_time = end - start
        file=open(RESULTS + "ipv4_fuzzer_results_%s.txt" % run_num, "w")
        file.write("start time: %s \n" % start)
        file.write("end time: %s \n" % end)
        file.write("execution time: %s \n" % execution_time)
        file.write("Number of packets sent: %s \n" % run)
        file.write("first reward seen after %s runs. \n" % first_reward_seen)
        file.write("first reward seen after %s seconds. \n" % first_bug_time)
        file.write("\n")
        file.close()
        env.clean_up()
        time.sleep(1)
        del env
        time.sleep(5)
        sys.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('run_num', type=int, help="The number of the query with which the Agent should run")
    parser.add_argument('netpaxos', type=int, help="Flag to set if netpaxos applications are executed")
    args = parser.parse_args()
    run_num = args.run_num
    netpaxos = args.netpaxos
    if netpaxos == 1:
        run(run_num, True)
    else:
        run(run_num, False)



