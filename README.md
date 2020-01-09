# P6

## Disclaimer

As per the NDA with Barefoot Networks, it is not allowed to publicly release any file written for Barefoot Tofino Switch and Barefoot Tofino Model. Files related to Barefoot Tofino are indicated by  _tofino as part of the file name.

## Getting Started

These instructions will help you to get the project up and running on your local machine.

### Prerequisites

In order to run P6, make sure to have Vagrant installed. If not already installed, go to [Vagrant Website](https://www.vagrantup.com/intro/getting-started/install.html) and follow the instructions to install it.
In addition install screen by running the following:

```
$ sudo apt-get install screen
```

### Installing

The following describes how to install necessary Python packages for running the project. The list of dependecies is provided with the requirements_36.txt and requirements_2.txt files, respectively. In order to install the packages create a virtualenv for Python 2.7 and Python 3.6 and install the packages by running the following:

```
$ python2.7 -m venv PATH-TO-P6/controller_venv/
$ PATH-TO-P6/controller_venv/bin/pip install -r ./requirements_2.txt

$ python3.6 -m venv PATH-TO-P&/p4rl_venv36/
$ PATH-TO-P6/p4rl_venv36/bin/pip3.6 install -r ./requirements_36.txt
```

Create a folder for the logs in P6 folder:

```
$ mkdir PATH-TO-P6/logs
```

## Running P6 Experiments

For running the experiments and replicating the provided results, make sure to adjust the paths to match your environment in the following files:

```
run_files/frame_sequential.sh
run_files/automate_testing.sh
run_files/automate_ipv4_baseline_tests.sh
run_files/automate_naive_baseline_tests.sh
run_files/frame_tofino_run.sh
run_files/all_kill.sh
run_files/kill_processes.sh
run_files/ordering.py
run_files/format_ipv4_results_to_csv.py
run_files/format_naive_results_to_csv.py
run_files/format_results_to_csv.py
run_files/run_ipv4.sh
run_files/run_ipv4_init.sh
run_files/run_naive.sh
run_files/run_naive_init.sh
run_files/run_normal.sh
run_files/run_with_initialization.sh
```

Then run 

```
$ vagrant up
```

to start all necessary VMs.


After the VMs are up and running, run the frame_sequential.sh script in a screen session.

```
$ screen ./run_files/frame_sequential.sh
```

Leave the machine up and running and collect the results in a few days. The results can be found in the PATH-TO-P6/results/final_results.csv file. 

For parallelizing the work and massively reduce overall experiment run time, it is also possible to create multiple (8) copies of the vagrant environment and use the frame_run.sh, frame_ipv4_run.sh and frame_naive_run.sh scripts. The necessary Vagrant files can be found in the extra_vagrantfiles/ folder. Note it will be necessary to adjust the paths and vagrant commands in the following scripts after copying:

```
run_files/automate_testing.sh
run_files/automate_ipv4_baseline_tests.sh
run_files/automate_naive_baseline_tests.sh
run_files/all_kill.sh
run_files/kill_processes.sh
run_files/ordering.py
run_files/format_ipv4_results_to_csv.py
run_files/format_naive_results_to_csv.py
run_files/format_results_to_csv.py
run_files/run_ipv4.sh
run_files/run_ipv4_init.sh
run_files/run_naive.sh
run_files/run_naive_init.sh
run_files/run_normal.sh
run_files/run_with_initialization.sh

```

