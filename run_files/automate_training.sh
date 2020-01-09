#!/bin/bash

source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4/P4/basic.p4'}
netpaxos=${2:-0}
random_act=${3:-0}

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4/

for iterator in {0..9}
do
  for case_iterator in {1..9}
  do
      #Run the tests with initialization
      ./run_files/run_training_with_initialization.sh $source_code $case_iterator 0 $netpaxos $random_act &
      #Wait so the test has time to finish
      wait
    cd /home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results
    mv "./DDQN_prio_replay_results_$case_iterator"_original_run.txt "../backup/simple_agent_training/DDQN_prio_replay_results_$case_iterator"_original_run_test_$iterator
    cd /home/apoorv/p4rl_tarantula/RL_for_P4
  done
done

echo "TRAINING FINISHED"
