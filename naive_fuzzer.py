
import time
from net_env_multi_actions_full_new_reward import networkEnv
import numpy as np
import argparse
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
            run +=1
            reward = env.check_random_reward()
            if reward==1 and not first_reward:
                first_reward = True
                first_reward_seen = run 
                first_bug_time = time.time() - start
                break
        print("loop finished")
        end = time.time()
        execution_time = end - start
        file=open(RESULTS + "naive_fuzzer_results_%s.txt" % run_num, "w")
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

