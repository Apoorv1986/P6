#!/usr/bin/env python
import sys
import struct
import os
import time
import csv


#Global variables
LOC_RESULTS_FILE =    '/home/apoorv/p4rl_tarantula/RL_for_P4/results/loc_results.csv'
DET_RESULTS_FILE =    '/home/apoorv/p4rl_tarantula/RL_for_P4/results/detection_results.csv'
SUSPICIOUSNESS_FILE = '/home/apoorv/p4rl_tarantula/RL_for_P4/results/susp-results.csv'
PATCHER_FILE =        '/home/apoorv/p4rl_tarantula/RL_for_P4/results/patcher_results.csv'
PACKETS_GENERATED =   '/home/apoorv/p4rl_tarantula/RL_for_P4/results/packets_generated.csv'
CUMULATIVES_FOR_PLOT ='/home/apoorv/p4rl_tarantula/RL_for_P4/results/cumulative.csv'
#Global number of testcases created by the given test
number_of_testcases = 10

#This functions cleans the results of previous tests from the result files
def clean_results():
  results = open(LOC_RESULTS_FILE,"w")
  results.close()
  results = open(DET_RESULTS_FILE,"w")
  results.close()
  results = open(SUSPICIOUSNESS_FILE,"w")
  results.close()
  results = open(PATCHER_FILE,"w")
  results.close()
  results = open(PACKETS_GENERATED,"w")
  results.close()


#This function collects the localization results
def localization_results():
  global number_of_testcases
  localization_times = []
  results_to_write = []
  iterator = 1
  #Iterate through the localization results test file and collect localization times for each line
  while iterator < number_of_testcases:
    loc_results = open(LOC_RESULTS_FILE,"a+")
    localization_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/localization_result_%d'%(iterator),"r")

    for line in localization_file:
      #Default value is 100000.00000, so if it is in the line, it was not executed according to our Tarantula implementation
      #For the first iteration we just write the results into the result file
      if '100000.00000' not in line and iterator == 1:
        loc_time = line[19:26]
        loc_results.write("%s\n"%loc_time)
      elif iterator == 1:
        loc_results.write("\n")
      elif '100000.00000' not in line:
        loc_time = line[19:26]
        localization_times.append(loc_time)

    #Close the files
    localization_file.close()
    loc_results.close()

    #At later iterations we have to save the content of the file first, and write it back together with the newly obtained results
    if iterator > 1:
      loc_results = open(LOC_RESULTS_FILE,"r")
      iterator3 = 1
      #Reading in the current lines and saving them
      #We save each line, if there was no localization, we save it as an empty line
      for line in loc_results:
        if iterator3 < len(localization_times):
          line2 = "%s;%s\n"%(line[:-1],localization_times[iterator3])
        else:
          line2 = "%s;\n" %line[:-1]
        results_to_write.append(line2)
        iterator3 += 1

     #Close the file and re-open it to write back all the results obtained
      loc_results.close()
      loc_results = open(LOC_RESULTS_FILE,"w")
      iterator3 = 0
      while iterator3 < len(results_to_write):
        loc_results.write(results_to_write[iterator3])
        iterator3 += 1
      #Close the file for the last time
      loc_results.close()

    #Empty the results_to_write list for the next testcase
    while len(results_to_write) > 0:
      results_to_write.pop()
    #Empty the localization_times lists for the next testcase
    while len(localization_times) > 0:
      localization_times.pop()
    iterator += 1


#This function collects the detection times from the testcase-results
def detection_times():
  global number_of_testcases
  iterator = 1
  found = False
  #Iteratre through the different result files
  while iterator < number_of_testcases:
    testcase_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/naive_fuzzer_results_%d_original_run.txt'%iterator,"r")
    results_file = open(DET_RESULTS_FILE,"a+")
    #Iterate through all lines in the file
    for line in testcase_file:
      if 'execution time' in line:
        helper = line.split(':')
        helper2 = float(helper[1].lstrip())
        found = True
      if 'first reward seen after 0 runs' in line:
        found = False
    if found is False:
      helper2 = 100000.0
      #If an error is detected we store it in the dedicated variables
      #We always check if the new detection was earlier than the current value
      #This way we ensure that we store only the earliest detection time for each type of errors
    if iterator == 1:
      results_file.write("sent_checksum;%.5f\n"%helper2)
    elif iterator == 2:
      results_file.write("recv_checksum;%.5f\n"%helper2)
    elif iterator == 3:
      results_file.write("IP_version;%.5f\n"%helper2)
    elif iterator == 4:
      results_file.write("ihl_too_small;%.5f\n"%helper2)
    elif iterator == 5:
      results_file.write("total_len_smaller_than_ihl_indicates;%.5f\n"%helper2)
    elif iterator == 6:
      results_file.write("sent_ttl;%.5f\n"%helper2)
    elif iterator == 7:
      results_file.write("recv_ttl;%.5f\n"%helper2)
    elif iterator == 8:
      results_file.write("mac_swap;%.5f\n"%helper2)
    elif iterator == 9:
      results_file.write("port_or_dst_mac;%.5f\n"%helper2)


    testcase_file.close()
    results_file.close()
    iterator += 1

def patcher():
  global number_of_testcases
  results_file = open(PATCHER_FILE,"a+")
  iterator = 1
  #Iterate through the testcase log files
  while iterator < number_of_testcases:
    testcase_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/patcher_execution_time_%d'%(iterator),"r")
    for line in testcase_file:
      helper = line
      results_file.write(helper)
    testcase_file.close()
    iterator += 1
  results_file.close()

def suspiciousness():
  global number_of_testcases
  #Define the countign variables for the different cases
  true_positives = 0
  false_positives = 0
  false_negatives = 0
  true_negatives = 0
  yellow_cases = 0


  iterator = 1
  #Iterate through the testcase log files
  while iterator < number_of_testcases:
    previous_line = 'asd'
    #Open the files to write out the results and read in data from the logs
    loc_results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/localization_result_%d'%iterator,"r")

    #Iterate thourgh the localization log file line by line
    for line in loc_results_file:
      #First check the liens with the highest suspiciousness scores:
      if 'Suspiciousness: 1.00' in line:
        if ('hdr.ipv4.ttl' in line and '-' in line and '1' in line) or ('control' in line and 'Verify' in line) or ('if' in line and 'isValid' in line and 'hdr' in line) or ( 'apply' in line and '{' in line and '}' in line and 'control' in previous_line): #and 'Verify' in previous_line):
          true_positives += 1
        else:
          false_positives += 1
      elif 'Suspiciousness: 0.50' in line:
        yellow_cases += 1
      elif 'Suspiciousness: 0.00' in line:
        if ('hdr.ipv4.ttl' in line and '-' in line and '1' in line) or ('control' in line and 'Verify' in line) or ( 'apply' in line and '{' in line and '}' in line and 'control' in previous_line and 'Verify' in previous_line) or ('if' in line and 'isValid' in line and 'hdr' in line):
          false_negatives += 1
        else:
          true_negatives +=1
      else:
        print "We have not programmed this path yet - should never appear"
      previous_line = line
    #Close the files before the next iteration
    loc_results_file.close()
    iterator += 1

  results_file = open(SUSPICIOUSNESS_FILE,"a+")
  results_file.write("true_positives;%d\n"%true_positives)
  results_file.write("true_negatives;%d\n"%true_negatives)
  results_file.write("false_negatives;%d\n"%false_negatives)
  results_file.write("false_positives;%d\n"%false_positives)
  results_file.close()


#This function collects the information about how many packets were generated during the tests
def packets_generated():
  global number_of_testcases
  iterator = 1

  results_file = open(PACKETS_GENERATED,"a")
  #Iteratre through the different result files
  while iterator < number_of_testcases:
    testcase_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/naive_fuzzer_results_%d_original_run.txt'%iterator,"r")
    for line in testcase_file:
      if "Number of packets sent" in line:
        helper = line.split(':')
        helper2 = int(helper[1].lstrip())
        results_file.write("%d\n"%helper2)

    iterator += 1
  results_file.close()

def cumulative():
  global number_of_testcases
  iterator = 1
  total_of_cumulatives = []
  average = []

  results_file = open(CUMULATIVES_FOR_PLOT,"a")
  #Iteratre through the different result files
  while iterator < number_of_testcases:
    testcase_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/naive_fuzzer_results_%d_original_run.txt'%iterator,"r")
    for line in testcase_file:
      if "Cumulative Reward for plotting" in line:
        helper = line.split(':')
        helper2 = helper[1].lstrip()
        helper2 = helper2[1:-3]
        helper2 = helper2.replace(' ','')
        helper2 = helper2.replace(',',';') #TODO: REMOVE LATER, ONLY USED TO CONVERT THE CURRENTLY AVAILABLE DATASET TO FUTURE FORM
        helper3 = helper2.split(';')
    iterator2 = 0
    if iterator == 1:
      while iterator2 < 100:
        total_of_cumulatives.append(int(helper3[iterator2]))
        average.append(0.0)
        iterator2 += 1
    else:
      while iterator2 < 100:
        helper = total_of_cumulatives[iterator2]+ int(helper3[iterator2])
        total_of_cumulatives[iterator2] = helper
        iterator2 += 1
    iterator += 1
  iterator = 0
  while iterator < 100:
    average[iterator] = (float(total_of_cumulatives[iterator]) / float(number_of_testcases))
    if iterator == 0:
      results_file.write("Avg cumulative for plot;%.5f"%average[iterator])
    elif iterator == 99:
      results_file.write(";%.5f\n"%average[iterator])
    else:
      results_file.write(";%.5f"%average[iterator])

    iterator += 1
  results_file.close()



def main():
  #First we clean the results of previous tests
  clean_results()

  #Then collect the localization results
  localization_results()
  #Now collect the detection times
  detection_times()
  #Now collect the number of packets generated during the test
  packets_generated()
  #Now calculate true-positives, false-positives and false-negatives for the localization
  suspiciousness()
  #Now collect the commulative training results
  #cumulative()
  #And last collect the execution times for the patcher
  patcher()


if __name__ == '__main__':
    main()

