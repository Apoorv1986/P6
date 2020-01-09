import random
import time
import numpy as np
from collections import deque
from keras.models import Sequential,load_model
from keras.layers import Dense
from keras.optimizers import Adam, Adadelta, SGD
from keras.initializers import RandomUniform
import struct
from net_env_multi_actions_full_new_reward import networkEnv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import argparse
import re
import os
############### Global config: paths, etc. ###############

FIGURES = "/vagrant/figures/"
MODEL = "/vagrant/model_save/"
RESULTS = "/vagrant/results/"
#RESULTS = "./"


############### Hyperparameters & Config #################

VERBOSE = False
counter_=0
results_num = 0
# GAMMA war 0.95
GAMMA = 0.99
# LR war 0.0001 vorher
#LEARNING_RATE = 0.0001
LEARNING_RATE = 0.00025
N_NEURONS = 128

MEMORY_SIZE = 1000000
BATCH_SIZE = 20

#EXPLORATION_MAX = 1.0
#EXPLORATION_MIN = 0.01
#EXPLORATION_DECAY = 0.995

EXPLORATION_MAX = 1.0
EXPLORATION_MIN = 0.01
EXPLORATION_TEST = 0.02
EXPLORATION_STEPS = 50
EXPLORATION_DECAY = (EXPLORATION_MAX-EXPLORATION_MIN)/EXPLORATION_STEPS


pre_train_steps = 50
max_epLength = 2
num_episodes = 200
update_freq = 4
TARGET_NETWORK_UPDATE_FREQUENCY = 12

q_value_save = []
OPTIMIZER = SGD(lr=LEARNING_RATE)
n_input = 5 # Data input in our case is 20 Bytes converted to 5 4-Byte floats, hence 5 is the input size,
            # other values to be tested
n_actions = 20 # number of actions in our RL env
jList = []
rList = []
cumulative_reward = []


def reset_values():
    q_value_save.clear()
    jList.clear()
    rList.clear()
    cumulative_reward.clear()

class DDQNSolver:

    def __init__(self, load_mod=False, run_number=3):
        self.steps = 0
        self.counter = 0
        self.run_number = run_number
        print(self.run_number)
        self.load_mod = load_mod
        self.exploration_rate = EXPLORATION_MAX
        initializer = RandomUniform(minval=0, maxval=0.1, seed=None)
        self.action_distr = np.zeros(n_actions)
        self.predicted_a = np.zeros(n_actions)
        self.action_space = n_actions
        self.memory = deque(maxlen=MEMORY_SIZE)
        if not self.load_mod:
            self.ddqn = Sequential()
            self.ddqn.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', input_dim=n_input, activation="tanh"))
            self.ddqn.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn.add(Dense(self.action_space, activation="softmax"))
            self.ddqn.compile(loss="categorical_crossentropy", optimizer=OPTIMIZER)

            self.ddqn_target = Sequential()
            self.ddqn_target.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', input_dim=n_input, activation="tanh"))
            self.ddqn_target.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn_target.add(Dense(N_NEURONS, kernel_initializer=initializer,
                                bias_initializer='zeros', activation="tanh"))
            self.ddqn_target.add(Dense(self.action_space, activation="softmax"))
            self.ddqn_target.compile(loss="categorical_crossentropy", optimizer=OPTIMIZER)
        else:
            self.ddqn = None
            self.ddqn_target = None
            self.load()


    def __del__(self):
        print("DDQN Solver deleted")


# changed paths according to global config paths
    def load(self):
        print("attempting to load model...")
        #try:
        self.ddqn = load_model(MODEL + "DDQN_online_agent_%s.h5" % self.run_number)
        self.ddqn_target = load_model(MODEL + "DDQN_target_agent_%s.h5" % self.run_number)
        #except Exception as e:
        #    print(e)
        print("model loaded")
        return


    def save_model(self):
        print("reached save")
        try:    
            while os.path.isfile(MODEL + "DDQN_online_agent_%s_%s.h5" % (self.run_number, self.counter)) or os.path.isfile(MODEL + "DDQN_target_agent_%s_%s.h5" % (self.run_number, self.counter)):
                self.counter+=1
        except Exception as e: 
            print(e)
        print("passed the if ...")
        try:
            self.ddqn.save(MODEL + "DDQN_online_agent_%s_%s.h5" % (self.run_number, self.counter))
            self.ddqn_target.save(MODEL + "DDQN_target_agent_%s_%s.h5" % (self.run_number, self.counter))
        except Exception as e:
            print(e)
        print("reached save and saved it here: %s" % str(MODEL + "DDQN_target_agent_%s_%s.h5" % (self.run_number, self.counter)))
#        self.counter+=1
        return

    def remember(self, state, action, reward, next_state, done):
        #print(state,action,reward,next_state,done)
        self.memory.append((state, action, reward, next_state, done))
        if len(self.memory) > MEMORY_SIZE:
            self.memory.pop(0)


    def act_random(self):
        return random.randrange(self.action_space)

    def act_load(self, state):
        state = state.reshape((1, n_input))
        # print(state)
        q_values = self.ddqn.predict(state)
        q_value_save.append(q_values)
        self.predicted_a[np.argmax(q_values[0])] = int(self.predicted_a[np.argmax(q_values[0])] + 1)
        #print(self.predicted_a)
        #print(q_values)
        return np.argmax(q_values[0])

    def act(self, state):
        if np.random.rand() < self.exploration_rate:
            return random.randrange(self.action_space)
        #for i in range(0,5):
        #    state[i]=(state[i]-(1.2*(10**-38)))/(3.4*10**38 - 1.2*(10**-38))
        state = state.reshape((1, n_input))
        #print(state)

        q_values = self.ddqn.predict(state)
        q_value_save.append(q_values)

        #print("qvalues: ", q_values)
        # predicted_a is used to save predicted best actions for given states
        self.predicted_a[np.argmax(q_values[0])] = int(self.predicted_a[np.argmax(q_values[0])] + 1)
        #print(self.predicted_a)
        #print(np.argmax(q_values[0]))
        return np.argmax(q_values[0])

    def _reset_target_network(self):
        self.ddqn_target.set_weights(self.ddqn.get_weights())

    def experience_replay(self):
        self.steps += 1
        if len(self.memory) < BATCH_SIZE or self.steps < pre_train_steps:
            return
        #batch = random.sample(self.memory, BATCH_SIZE)

        # uncomment
        buffer = sorted(self.memory, key=lambda replay: replay[2], reverse=True)

        #print("sorted buffer: ", buffer)

        # uncomment
        p = np.array([0.85 ** i for i in range(len(buffer))])
        sum_p = sum(p)

        #p = list(p)
        #for i in range(len(buffer)-len(p)):
        #    p.append(0)
        #p = np.array(p)
        # print(buffer)

        # uncomment
        for i in range(0, len(p)):
            p[i] = p[i] / sum_p


        #print(p)

        # uncomment
        sample_ids = np.random.choice(np.arange(len(buffer)), size=BATCH_SIZE, p=p)
        batch = [buffer[id] for id in sample_ids]

        #batch = np.reshape(sample_output, [BATCH_SIZE, 5])
        if self.steps % update_freq == 0:
            for state, action, reward, state_next, terminal in batch:
                #print(state, action, reward, state_next, terminal)
                q_update = reward
                #print("update with reward: ", reward)
                if not terminal:
                    state_next = state_next.reshape((1,n_input))
                    q_update = (reward + GAMMA * np.amax(self.ddqn_target.predict(state_next)[0]))

                state = state.reshape((1,n_input))
                q_values = self.ddqn.predict(state)
                q_values[0][action] = q_update

                self.ddqn.fit(state, q_values, verbose=0)

        #print("steps: ", self.steps)
        if self.steps > pre_train_steps:
            self.exploration_rate -= EXPLORATION_DECAY

        self.exploration_rate = max(EXPLORATION_MIN, self.exploration_rate)

        if self.steps % TARGET_NETWORK_UPDATE_FREQUENCY == 0:
            self._reset_target_network()

def processState(states):
    if VERBOSE:
        print("State in bytes: ", bytes(states))

    if len(states) == 19:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
    elif len(states) == 18:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
    elif len(states) == 17:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
    elif len(states) == 16:
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(states)))
        states = bytes(bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(bytes(b'\x00')) + bytearray(
            bytes(states)))

    if VERBOSE:
        print("State in bytes: ",  bytes(states))

    byte_to_float = []
    i = 0
    for i in [0,4,8,12,16]:
        byte_to_float.append(struct.unpack('f', bytearray(states)[i:i+4]))
    return np.reshape(byte_to_float, [n_input])

def commarepl(matchobj):
    if matchobj.group(0) == ',': return ';'


def run(run_num, load_mod, netpaxos):
    with networkEnv(4, verbose=VERBOSE, netp=netpaxos) as env:

        env.reward_system.run = run_num
    #env = networkEnv(4, verbose=VERBOSE)
    #score_logger = ScoreLogger(ENV_NAME)
        ddqn_solver = DDQNSolver(load_mod=load_mod, run_number=run_num)
        start = time.time()
        run = 0
        first_reward = False
        first_reward_seen = 0
        first_bug_time = -1
        if not ddqn_solver.load_mod:
            for i in range(num_episodes):
                run += 1
                state = env.reset()
                state = processState(state)
                step = 0
                rAll = 0
                while step < max_epLength:
                    d = False
                    step += 1
                    #env.render()
                    action = ddqn_solver.act(state)

                    # dqn_solver.action_distr is only for keeping track of how often each
                    # of the available actions were chosen in the course of training
                    ddqn_solver.action_distr[action] = int(ddqn_solver.action_distr[action] + 1)
                    state_next, reward = env.execute(action)
                    if step == max_epLength:
                        terminal = True
                        reward = env.check_reward()
                    else:
                        terminal = False

                    if reward is not None:
                        d = True
                    else:
                        reward = 0
                   # if terminal:
                    #    print("reward before: ", reward)
                    #reward = reward if not terminal# else -reward
                    #if terminal:
                    #    print("reward now: ", reward)
                    state_next = processState(state_next)
                    #print("Reward before remember: ", reward)
                    #print("state before remember: ", state)
                    if reward==1 and first_reward==False:
                        first_reward = True
                        first_reward_seen = run
                        first_bug_time = time.time() - start
                    ddqn_solver.remember(state, action, reward, state_next, terminal)
                    state = state_next
                    ddqn_solver.experience_replay()
                    if terminal or d:
                        if run % 100 == 0:

                            print ("Run: " + str(run) + ", exploration: " + str(ddqn_solver.exploration_rate) + ", score: " + str(step))
                            print("Reward: ", reward)
                        rAll += reward
                        break

                rList.append(rAll)
                jList.append(step)
                cumulative_reward.append(sum(rList))
            print("calling save now .....")
            ddqn_solver.save_model()
        else:

            for i in range(num_episodes):
                run += 1
                state = env.reset()
                state = processState(state)
                step = 0
                rAll = 0
                while step < max_epLength:
                    d = False
                    step += 1
                    #env.render()
                    action = ddqn_solver.act_load(state)
                    #action = ddqn_solver.act_random()
                    ddqn_solver.action_distr[action] = int(ddqn_solver.action_distr[action] + 1)
                    state_next, reward = env.execute(action)
                    if step == max_epLength:
                        terminal = True
                        reward = env.check_reward()
                    else:
                        terminal = False
                    if reward is not None:
                        d = True
                    else:
                        reward = 0
                    if reward==1 and not first_reward:
                        first_reward = True
                        first_reward_seen = run
                        first_bug_time = time.time() - start
                        rAll += reward
                        break
                rList.append(rAll)
                jList.append(step)
                cumulative_reward.append(sum(rList))
                if first_reward:
                    break
                if run > 99:
                    break

        end = time.time()
        execution_time = end - start
        if first_reward_seen == 0:
            first_reward_seen = run
        t = np.arange(0.0, run, 1)
        s = cumulative_reward
        #print("Q Values over time: ", q_value_save)
        # changed path according to global config paths
        # TODO: change to write results in CSV file
        file=open(RESULTS + "DDQN_prio_replay_results_%s.txt" % results_num, "a")

        file.write(re.sub(r'[,]*',commarepl,"Action distribution: %s \n" % list(map(int, ddqn_solver.action_distr))))
        file.write(re.sub(r'[,]*',commarepl,"Number of actions per episode: %s \n" % sum(jList)))
        file.write(re.sub(r'[,]*',commarepl,"Predicted a: %s \n" % list(map(int, ddqn_solver.predicted_a))))
        file.write("Learning Rate used: %s \n" % LEARNING_RATE)
        file.write("Number of Neurons: %s \n" % N_NEURONS)
        file.write("Optimizer used: %s \n" % OPTIMIZER)
        file.write("Max number of steps: %s \n" % max_epLength)
        file.write("Cumulative Reward: %s \n" % max(cumulative_reward))
        file.write(re.sub(r'[,]*',commarepl,"Cumulative Reward for plotting: %s \n" % list(cumulative_reward)))
        file.write(re.sub(r'[,]*',commarepl,"X for plotting cumulative reward: %s \n" % list(t)))
        file.write("start time: %s \n" % start)
        file.write("end time: %s \n" % end)
        file.write("execution time: %s \n" % execution_time)
        file.write("Number of packets sent: %s \n" % first_reward_seen)
        file.write("first reward seen after %s runs. \n" % first_reward_seen)
        file.write("first reward seen after %s seconds. \n" % first_bug_time)
        file.write("\n")
        file.close()
        print("Cumulative Reward: %s" % max(cumulative_reward))
        print("Number of packets sent: %s" % first_reward_seen)
        print("Action distribution: ", list(map(int, ddqn_solver.action_distr)))
        print("Number of actions per episode: ", sum(jList))
        print("Predicted a: ", list(map(int, ddqn_solver.predicted_a)))
        print("Learning Rate used: ", LEARNING_RATE)
        print("Number of Neurons: ", N_NEURONS)
        print("Optimizer used: ", OPTIMIZER )
        print("Max number of steps: ", max_epLength)
        if not ddqn_solver.load_mod:
            fig, ax = plt.subplots()

            ax.plot(t, s)
            ax.set(xlabel='Number of Steps', ylabel='Cumulative Reward')
            # changed paths according to global config
            fig.savefig(FIGURES + "DDQN_cumulative_reward_%s_%s.png" % (run_num, ddqn_solver.counter))
            #plt.show()
            fig.clear()

        #plt.gcf().clear()
        #plt.clf()
        #plt.cla()
        #plt.close()
        #plt.plot(cumulative_reward)
        # plt.scatter(data_x,[3427, 3428, 3398, 3444 , 3401, 3483, 3477 ,3392, 3411, 3435])
        #plt.xlabel('Number of Steps', fontsize=16)
        #plt.ylabel('Cumulative Reward', fontsize=16)

        #plt.axis([0, num_episodes + 1000, 0, max(cumulative_reward) + 500])
        # plt.axis([0, 11, 3000, 3600])
        #plt.savefig("DDQN_cumulative_reward_%s.png" % counter_)
        #plt.show(block=False)
        #plt.clf()
        #plt.gcf().clear()
        #plt.clf()
       # plt.cla()
        #plt.close(plt.gcf())
        #plt.close()

        env.clean_up()
        time.sleep(1)
        del env

def run_random(run_num):
    with networkEnv(4, verbose=VERBOSE) as env:
        start = time.time()
        env.reward_system.run = run_num
        run = 0
        first_reward = False
        first_reward_seen = 0
        first_bug_time = -1
        for i in range(num_episodes):
            run += 1
            rAll = 0
            reward = env.check_random_reward()
            if reward is not None:
                d = True
            else:
                reward = 0

            if reward == 1 and first_reward == False:
                first_reward = True
                first_reward_seen = run
                first_bug_time = time.time() - start

            rAll += reward
            if first_reward:
                break
            if run > 199:
                break

            rList.append(rAll)
           #jList.append(step)
            cumulative_reward.append(sum(rList))
            print(cumulative_reward)
            if first_reward:
                break
            if run > 99:
                break

        t = np.arange(0.0, num_episodes, 1)
        s = cumulative_reward
        end = time.time()
        #TODO: change path according to global config
        #TODO: change to save reuslts in CSV
        file = open(RESULTS + "full_random_results_%s.txt" % results_num, "a")

        execution_time = end - start

        file.write("Cumulative Reward: %s \n" % max(cumulative_reward))
        file.write(re.sub(r'[,]*',commarepl,"Cumulative Reward for plotting: %s \n" % list(cumulative_reward)))
        file.write(re.sub(r'[,]*',commarepl,"X for plotting cumulative reward: %s \n" % list(t)))
        file.write("start time: %s \n" % start)
        file.write("end time: %s \n" % end)
        file.write("execution time: %s \n" % execution_time)
        file.write("first reward seen after %s runs. \n" % first_reward_seen)
        file.write("first reward seen after %s seconds. \n" % first_bug_time)
        file.write("\n")
        file.close()



        fig, ax = plt.subplots()

        ax.plot(t, s)
        #changed according to paths in global config
        ax.set(xlabel='Number of Steps', ylabel='Cumulative Reward')
        fig.savefig(FIGURES + "Random_cumulative_reward_%s_%s.png" % (counter_))

        fig.clear()

        env.clean_up()
        time.sleep(1)
        del env

    return

def run_simple(run_num, load_mod, netpaxos):
    with networkEnv(4, verbose=VERBOSE, loc=False, netp=netpaxos) as env:
          
        env.reward_system.run = run_num
    #env = networkEnv(4, verbose=VERBOSE)
    #score_logger = ScoreLogger(ENV_NAME)
        ddqn_solver = DDQNSolver(load_mod=load_mod, run_number=run_num)
        start = time.time()
        run = 0
        first_reward = False
        first_reward_seen = 0
        first_bug_time = -1
        rList = []
        for i in range(num_episodes):
            run += 1
            state = env.reset()
            state = processState(state)
            step = 0
            rAll = 0
            while step < max_epLength:
                d = False
                step += 1
                #env.render()
                #action = ddqn_solver.act_load(state)
                #print("executing random action: ")
                action = ddqn_solver.act_random()
                #print("action num: ", action)
                ddqn_solver.action_distr[action] = int(ddqn_solver.action_distr[action] + 1)
                state_next, reward = env.execute(action)
                if step == max_epLength:
                    terminal = True
                    reward = env.check_reward()
                else:
                    terminal = False
                if reward is not None:
                    d = True
                else:
                    reward = 0
                if reward==1 and not first_reward:
                    first_reward = True
                    first_reward_seen = run
                    first_bug_time = time.time() - start
                    rAll += reward
                    #break
        #        time.sleep(0.2)
            #global rList
            rList.append(reward)
            jList.append(step)
            cumulative_reward.append(sum(rList))
            #if first_reward:
             #   break
            if run > 199:
                break
            # TODO: change to write results in CSV file
        end = time.time()
        execution_time = end - start
        if first_reward_seen == 0:
            first_reward_seen = run
        t = np.arange(0.0, run, 1)
        s = cumulative_reward

        file=open(RESULTS + "DDQN_prio_replay_results_%s.txt" % results_num, "a")

        file.write(re.sub(r'[,]*',commarepl,"Action distribution: %s \n" % list(map(int, ddqn_solver.action_distr))))
        file.write(re.sub(r'[,]*',commarepl,"Number of actions per episode: %s \n" % sum(jList)))
        file.write(re.sub(r'[,]*',commarepl,"Predicted a: %s \n" % list(map(int, ddqn_solver.predicted_a))))
        file.write("Learning Rate used: %s \n" % LEARNING_RATE)
        file.write("Number of Neurons: %s \n" % N_NEURONS)
        file.write("Optimizer used: %s \n" % OPTIMIZER)
        file.write("Max number of steps: %s \n" % max_epLength)
        file.write("Cumulative Reward: %s \n" % max(cumulative_reward))
        file.write(re.sub(r'[,]*',commarepl,"Cumulative Reward for plotting: %s \n" % list(cumulative_reward)))
        file.write(re.sub(r'[,]*',commarepl,"X for plotting cumulative reward: %s \n" % list(t)))
        file.write("start time: %s \n" % start)
        file.write("end time: %s \n" % end)
        file.write("execution time: %s \n" % execution_time)
        file.write("Number of packets sent: %s \n" % first_reward_seen)
        file.write("first reward seen after %s runs. \n" % first_reward_seen)
        file.write("first reward seen after %s seconds. \n" % first_bug_time)
        file.write("\n")
        file.close()
        print("Cumulative Reward: %s" % max(cumulative_reward))
        print("Number of packets sent: %s" % first_reward_seen)
        print("Action distribution: ", list(map(int, ddqn_solver.action_distr)))
        print("Number of actions per episode: ", sum(jList))
        print("Predicted a: ", list(map(int, ddqn_solver.predicted_a)))
        print("Learning Rate used: ", LEARNING_RATE)
        print("Number of Neurons: ", N_NEURONS)
        print("Optimizer used: ", OPTIMIZER )
        print("Max number of steps: ", max_epLength)
        env.clean_up()
        time.sleep(1)
        del env



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('run_num', type=int, help="The number of the query with which the Agent should run")
    parser.add_argument('load_mod', type=int, help="Flag to set if Agent should use existing model")
    parser.add_argument('netpaxos', type=int, help="Flag to set if netpaxos applications are executed")
    parser.add_argument('random_act', type=int, help="Flag to set if Agent should only use random action selection")

    args = parser.parse_args()
    run_num = args.run_num
    trained = args.load_mod
    netpaxos = args.netpaxos
    random_act = args.random_act
    if trained == 0:
        load_mod = False
    elif trained == 1:
        load_mod = True
    else:
        print("command line argument out of range (trained != 0 && trained != 1 )")
    print("run number: ", run_num)
    print("load model? ", load_mod)

    results_num = run_num
    #DDQN
    #changed path according to global config
    #TODO: change to save config in separate file linkable to the CSV results
    file = open(RESULTS + "DDQN_prio_replay_results_%s.txt" % results_num, "w")
    #Random

    #file = open("full_random_results_%s.txt" % results_num, "w")
    #file.write("Random run: \n")
    file.write("Parameters used: \n")
    file.write("Gamma: %s \n" % GAMMA)
    file.write("Learning Rate: %s \n" % LEARNING_RATE)
    file.write("Number of Neurons: %s \n" % N_NEURONS)
    file.write("Memory size: %s \n" % MEMORY_SIZE)
    file.write("Batch Size: %s \n" % BATCH_SIZE)
    file.write("Exploration Max: %s \n" % EXPLORATION_MAX)
    file.write("Exploration Min: %s \n" % EXPLORATION_MIN)
    file.write("Exploration Test: %s \n" % EXPLORATION_TEST)
    file.write("Exploration Steps: %s \n" % EXPLORATION_STEPS)
    file.write("Exploration Decay: %s \n" % EXPLORATION_DECAY)
    file.write("Pre Train Steps: %s \n" % pre_train_steps)
    file.write("Max EP Length: %s \n" % max_epLength)
    file.write("Number of Episodes: %s \n" % num_episodes)
    file.write("Update Frequency: %s \n" % update_freq)
    file.write("Target Network Update Frequency: %s \n" % TARGET_NETWORK_UPDATE_FREQUENCY)
    file.write("\n")
    file.write("\n")
    file.write("\n")

    file.close()
#    run(run_num, load_mod)
    if random_act == 1:
        if netpaxos == 1:
            run_simple(run_num, load_mod, True)
        else:
            run_simple(run_num, load_mod, False)
    else:
        if netpaxos == 1:
            run(run_num, load_mod, True)
        else:
            run(run_num, load_mod, False)
    #run_number = 4
    # for i in range(2):
    #      #time.sleep(2)
    #      reset_values()
    #      run_random(run_num=run_number)
    #      #run(run_num=run_number)
    #      counter_+=1
    #      run_number+=1
    #      gc.collect()

