#!/usr/bin/env python
import sys
import struct
import os
import time
import csv


#Global variables
CUMULATIVES_FOR_PLOT ='/home/apoorv/p4rl_tarantula/RL_for_P4/results/cumulative.csv'
#Global number of testcases created by the given test
number_of_testcases = 9

#This functions cleans the results of previous tests from the result files
def clean_results():
  results = open(CUMULATIVES_FOR_PLOT,"w")
  results.close()


def cumulative():
  global number_of_testcases
  iterator = 1
  total_of_cumulatives = []
  average = []

  testcase_iterator = 1
  while testcase_iterator < 10:
    results_file = open(CUMULATIVES_FOR_PLOT,"a+")
    #Iteratre through the different result files
    iterator = 0
    while iterator < number_of_testcases:
      testcase_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/backup/training_data/DDQN_prio_replay_results_%d_original_run_test_%d'%(testcase_iterator,iterator),"r")
      for line in testcase_file:
        if "Cumulative Reward for plotting" in line:
          helper = line.split(':')
          helper2 = helper[1].lstrip()
          helper2 = helper2[1:-3]
          helper2 = helper2.replace(' ','')
          helper2 = helper2.replace(',',';')
          helper3 = helper2.split(';')
      iterator2 = 0
      if iterator == 0:
        while iterator2 < 200:
          total_of_cumulatives.append(int(helper3[iterator2]))
          average.append(0.0)
          iterator2 += 1
#        print total_of_cumulatives
      else:
        while iterator2 < 200:
          helper = total_of_cumulatives[iterator2]+ int(helper3[iterator2])
          total_of_cumulatives[iterator2] = helper
          iterator2 += 1
      iterator += 1
#    print total_of_cumulatives
    iterator = 0
    while iterator < 200:
      average[iterator] = (float(total_of_cumulatives[iterator]) / float(number_of_testcases))
      if iterator == 0:
        results_file.write("Avg cumulative for plot;testcase %d;%.5f"%(testcase_iterator,average[iterator]))
      elif iterator == 199:
        results_file.write(";%.5f\n"%average[iterator])
      else:
        results_file.write(";%.5f"%average[iterator])
      iterator += 1

    testcase_iterator += 1
#    print average
    while len(average) > 0:
      average.pop()
    while len(total_of_cumulatives) > 0:
      total_of_cumulatives.pop()
  results_file.close()



def main():
  #First we clean the results of previous tests
  clean_results()

  #Now collect the commulative training results
  cumulative()


if __name__ == '__main__':
    main()

