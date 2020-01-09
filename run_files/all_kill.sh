#!/bin/bash

#Kill the run scripts
sudo pkill -f automate_
sudo pkill -f run_with_initialization
sudo pkill -f run_normal
sudo pkill -f run_ipv4
sudo pkill -f run_naive
sudo pkill -f frame_
sleep 5


#Kill the processes on the controller, switch, and the hosts
echo "Killing environment 1"
vagrant ssh controller  -c 'sudo pkill -f mycontroller_l3switch.py' &
sleep 2
vagrant ssh s1          -c 'sudo pkill -f simple_switch_grpc' &
sleep 2
vagrant ssh source -c 'sudo pkill -f receive_h1.py' &
sleep 2
vagrant ssh sink1  -c 'sudo pkill -f receive_h2.py' &
sleep 2
vagrant ssh sink2  -c 'sudo pkill -f receive_h3.py' &
sleep 2
vagrant ssh agent  -c 'sudo pkill -f net_agent_multi_actions_full_keras_DDQN.py' &

#Kill all the things in environment 2
cd /home/apoorv/p4rl_tarantula/RL_for_P4_2/run_files/
echo "Killing environment 2"
./kill_processes.sh &
sleep 10

#Kill all the things in environment 3
cd /home/apoorv/p4rl_tarantula/RL_for_P4_3/run_files/
echo "Killing environment 3"
./kill_processes.sh &
sleep 10

#Kill all the things in environment 4
#cd /home/apoorv/p4rl_tarantula/RL_for_P4_4/run_files/
#echo "Killing environment 4"
#./kill_processes.sh &
#sleep 10

#Kill all the things in environment 5
cd /home/apoorv/p4rl_tarantula/RL_for_P4_5/run_files/
echo "Killing environment 5"
./kill_processes.sh &
sleep 10

#Kill all the things in environment 6
cd /home/apoorv/p4rl_tarantula/RL_for_P4_6/run_files/
echo "Killing environment 6"
./kill_processes.sh &
sleep 10

#Kill all the things in environment 7
cd /home/apoorv/p4rl_tarantula/RL_for_P4_7/run_files/
echo "Killing environment 7"
./kill_processes.sh &
sleep 10

#Kill all the things in environment 8
cd /home/apoorv/p4rl_tarantula/RL_for_P4_8/run_files/
echo "Killing environment 8"
./kill_processes.sh &
sleep 10

