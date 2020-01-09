#!/bin/bash

#Defining the variables used to execute the components throughout the script
source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4_2/P4/basic_tofino.p4'}
test_argument=${2:-'4'}
trained=${3:-'1'}
runtime_json=${4:-'/vagrant/runtime-configurations/basic.json'}
argument=0

#Covering the scenario where no source code is provided, but only an option
if [ $# -eq 0 ]
  then
    echo "No arguments provided, executing with default values"
elif [[ "$1" == *'.p4' ]]; then
    echo "P4 source code is: $source_code"
  if [[ $# -eq 2 ]]; then
    test_argument=$2
  elif [[ $# -eq 3 ]]; then
    test_argument=$2
    trained=$3
  elif [[ $# -eq 4 ]]; then
    test_argument=$2
    trained=$3
    runtime_json=$4
  else
    echo "Too many options provided"
    argument=1
  fi
else
  source_code='/home/apoorv/zsolt-thesis/tutorials/exercises/basic/solution/basic.p4'
  if [[ $# -eq 1 ]]; then
    test_argument=$1
  elif [[ $# -eq 2 ]]; then
    test_argument=$1
    trained=$2
  elif [[$# -eq 3]]; then
    test_argument=$1
    trained=$2
    runtime_json=$3
  else
    echo "Too many options provided"
    argument=1
  fi
fi

if [ $argument -eq 1 ]
  then
     echo "Correct usage of the run script:"
     echo "To execute the script correctly, you have to provide 4 optional arguments"
     echo "  -The first argument defines the source_code locations, the source code used by default is the basic.p4"
     echo "  -The second argument defines which test_case are we executing. This can take an integer value from 1 to 9"
     echo "  -The third argument defines if the Agent is already trained or shall be trained. This can take an integer value from 0 to 1"
     echo "  -The fourth argument defines the location of the runtime.json file, which is used to set up the control-plane configuration of the switch"
     exit 1
fi


#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4_2/
echo "killing old stuff"
#First we kill the controller and the switch
vagrant ssh agent2 -c 'sudo pkill -f net_' &
vagrant ssh s2 -c 'sudo pkill -f tofino' &
sleep 4
echo "starting switch now..."
#Starting switch S1
cd /home/apoorv/p4rl_tarantula/RL_for_P4_2/P4/
vagrant ssh s2 -c '/vagrant/P4/sxconfig-firstpart.sh' &
sleep 2
vagrant ssh s2 -c '/vagrant/P4/sxconfig-secondpart.sh ' &
sleep 90
echo "switch should be running now"
########## Setting up the environment ####################

#After a small time, start the agent to run the experiment
vagrant ssh agent2  -c "sudo /vagrant/p4rl_venv36/bin/python3.6 /vagrant/net_agent_multi_actions_full_keras_DDQN.py '$test_argument' '$trained'" &

#Wait for the agent to produce results
sleep 180 #Worst case: all 100 packets gets dropped --> 50 seconds + a small buffer for the initialization time of the agent

#Copy the previous results somewhere
cd /home/apoorv/p4rl_tarantula/RL_for_P4_2/
cp "./results/DDQN_prio_replay_results_$test_argument.txt" "./results/automated_results/DDQN_prio_replay_results_$test_argument"_original_run.txt

echo "RUN FINISHED $test_argument"
