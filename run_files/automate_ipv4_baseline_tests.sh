#!/bin/bash

source_code=${1:-'/home/apoorv/p4rl_tarantula/RL_for_P4/P4/basic.p4'}
runtime_json=${2:-'/vagrant/runtime-configurations/basic.json'}
netpaxos=${3:-0}

#Move to the correct directory
cd /home/apoorv/p4rl_tarantula/RL_for_P4/

#Run the tests 10 times, executing all test-cases for each run
for iterator in {0..9}
do
  for case_iterator in {1..9}
  do

    if [ $case_iterator -eq 1 ] && [ $iterator -eq 0 ]
    then
      #Run the tests with initialization
      ./run_files/run_ipv4_init.sh $source_code $case_iterator 1 $runtime_json $netpaxos > "./logs/automated_logs/ipv4_run_log_$iterator"_$case_iterator &
      #Wait so the test has time to finish
      wait
    else
      #Run the tests without initialization
      ./run_files/run_ipv4.sh $source_code $case_iterator 1 $runtime_json $netpaxos > "./logs/automated_logs/ipv4_run_log_$iterator"_$case_iterator &
      #Wait so the test has time to finish
      wait
    fi

    #Move the collected data to a new location, so the next iteration won't delete it
    cp "./logs/patcher_execution_times.txt" "./results/automated_results/patcher_execution_time_"$case_iterator
    cp "./logs/localization-results.txt" "./results/automated_results/localization_result_"$case_iterator
    echo "Iteration $iterator"$case_iterator
  done
  #Collect the localization and detection times
  python ./run_files/format_ipv4_results_to_csv.py
  cp ./results/detection_results.csv ./results/automated_results/detection_results_$iterator
  cp ./results/loc_results.csv ./results/automated_results/loc_results_$iterator
  cp ./results/patcher_results.csv ./results/automated_results/patcher_results_$iterator
  cp ./results/packets_generated.csv ./results/automated_results/packets_generated_$iterator
  cp ./results/susp-results.csv ./results/automated_results/susp-results_$iterator
done
#Collect the results from all the ten runs into a summarization file
python ./run_files/ordering.py

#After processing, save the original log files
cd /home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/
cp ./* /home/apoorv/p4rl_tarantula/RL_for_P4/results/backup/ipv4_tests/

echo "AUTOMATED TEST FOR IPV4-BASED FUZZER HAS FINISHED"

