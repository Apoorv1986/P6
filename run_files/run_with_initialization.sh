#!/bin/bash

#Defining the variables used to execute the components throughout the script
source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4/P4/basic.p4'}
test_argument=${2:-'3'}
trained=${3:-'0'}
runtime_json=${4:-'/vagrant/runtime-configurations/basic.json'}
netpaxos=${5:-0}
random_act=${6:-0}

#Covering the scenario where no source code is provided, but only an option
if [ $# -eq 0 ]
  then
    echo "No arguments provided, executing with default values"
elif [ $# -gt 6 ]; then
  echo "Too many arguments provided. Please check the function call."
  echo "The program will exit now"
  exit
elif [ $# -lt 6 ]; then
  echo "Not all the arguments are provided. This can cause the program to misbehave. Please either provide all the arguments or none of them"
  echo "The program will exit now"
  exit
else
  echo "Executing program with the provided arguments"
fi


#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4/

#Calling the code-reader to check for defined header types
python ./build/p4_code_reader_v2.py $source_code

#Before starting any component, make sure that they are not existing anymore
./run_files/kill_processes.sh > /dev/null 2>&1 &
sleep 5



#Compiling the code
echo "Compiling P4 code"
p4c-bm2-ss --p4v 16 --p4runtime-file ~/p4rl_tarantula/RL_for_P4/run_files/actual.p4info --p4runtime-format text -o ~/p4rl_tarantula/RL_for_P4/run_files/actual.json $source_code
#Copy compile results for later usage
cp $source_code ~/p4rl_tarantula/RL_for_P4/run_files/actual.p4

#Starting switch S1
echo "Starting s1 ..."
vagrant ssh s1 -c 'sudo simple_switch_grpc --log-file ./s1.log -i 0@enp0s9 -i 1@enp0s10 -i 2@enp0s16 --no-p4 -- --cpu-port 64' > /dev/null 2>&1 &
sleep 4

########## Setting up the environment ####################
echo "Starting the controller ..."
vagrant ssh controller -c "/vagrant/controller_venv/bin/python /vagrant/P4/mycontroller_l3switch.py --p4info /vagrant/run_files/actual.p4info --bmv2-json /vagrant/run_files/actual.json --runtime-json $runtime_json" > /home/apoorv/p4rl_tarantula/RL_for_P4/logs/controller_log & # > /dev/null 2>&1 &
sleep 4


#Start up the receivers on each host
echo "Starting the listeners on the hosts"
vagrant ssh source -c 'sudo /vagrant/hosts/receive_h1.py "192.168.0.2" "enp0s9" "enp0s8"'  > /dev/null 2>&1 &
vagrant ssh sink1  -c 'sudo /vagrant/hosts/receive_h2.py "192.168.0.5" "enp0s9" "enp0s8"'  > /dev/null 2>&1 &
vagrant ssh sink2  -c 'sudo /vagrant/hosts/receive_h3.py "192.168.0.9" "enp0s9" "enp0s8"'  > /dev/null 2>&1 &
sleep 5
#After a small time, start the agent to run the experiment
vagrant ssh agent  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/net_agent_multi_actions_full_keras_DDQN.py '$test_argument' '$trained' '$netpaxos' '$random_act'" &

#Wait for the agent to produce results
sleep 300 #Worst case: all 100 packets gets dropped --> 50 seconds + a small buffer for the initialization time of the agent


#############################################################################################################################
#############################################################################################################################
########################################## PATCH PHASE  ####################################################################
#############################################################################################################################
#############################################################################################################################

#Copy the previous results somewhere
cp "./results/DDQN_prio_replay_results_$test_argument.txt" "./results/automated_results/DDQN_prio_replay_results_$test_argument"_original_run.txt

#As we have the results, now its time to apply the patch and test if it has solved the issues or not
#First we kill the controller and the switch
vagrant ssh controller  -c 'sudo pkill -f mycontroller_l3switch.py' &
vagrant ssh s1 -c 'sudo pkill -f simple_switch_grpc ' &
sleep 4

#Compile the patch
echo "Compiling P4 code"
p4c-bm2-ss --p4v 16 --p4runtime-file ~/p4rl_tarantula/RL_for_P4/run_files/patch.p4info --p4runtime-format text -o ~/p4rl_tarantula/RL_for_P4/run_files/patch.json ~/p4rl_tarantula/RL_for_P4/build/patch.p4
#sleep 5

#Re-start the switch
./config_scripts/s1.sh > /dev/null 2>&1 &
sleep 4

#Re-start the controller
echo "Starting the controller ..."
vagrant ssh controller -c "/vagrant/controller_venv/bin/python /vagrant/P4/mycontroller_l3switch.py --p4info /vagrant/run_files/patch.p4info --bmv2-json /vagrant/run_files/patch.json --runtime-json $runtime_json" > /dev/null 2>&1 &
sleep 4

#Start the verification experiment
vagrant ssh agent  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/net_agent_multi_actions_full_keras_DDQN.py '$test_argument' '$trained' '$netpaxos' '$random_act'" &
#Wait for the agent to produce results
sleep 180 #Worst case: all 100 packets gets dropped --> 50 seconds + a small buffer for the initialization time of the agent


#Copy the previous results somewhere
cp "./results/DDQN_prio_replay_results_$test_argument.txt" "./results/automated_results/DDQN_prio_replay_results_$test_argument"_patched_run.txt

echo "RUN FINISHED"
