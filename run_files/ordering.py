#!/usr/bin/env python
import sys
import struct
import os
import time
import csv

#Global variables
FINAL_TEST_RESULTS = '/home/apoorv/p4rl_tarantula/RL_for_P4/results/final_results.csv'
errors_found = 0
errors_not_found = 0
maximum_testruns = 10

#This function clear the results of previous tests
def clean_test_results():
  file = open(FINAL_TEST_RESULTS,"w")
  file.close()


#this function collects the detection times from the previously run 10 tests
def detection_times_collector():
  iterator = 0
  lines_to_write = []
  #Iterate through the files
  while iterator < maximum_testruns:
    results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/detection_results_%d'%iterator,"r")

    #From each file collect the results of the tests to the corresponding variables
    for line in results_file:
      #For the first iteration just write it out
      if iterator == 1:
        final = open(FINAL_TEST_RESULTS,"a")
        final.write(line)
        final.close()
      #For later iterations we store the already existing values, and write it back with the new ones
      else:
        #Open the file for reading, and save all the currently stored results
        final = open(FINAL_TEST_RESULTS,"r")
        helper = line.split(';')
        for line2 in final:
          if helper[0] in line2:
            helper2 = line2[:-1] + ";" + helper[1]
            lines_to_write.append(helper2)
        #Close it
        final.close()

    if iterator > 1:
      #Re-open it to write all the results back
      final = open(FINAL_TEST_RESULTS,"w")
      iterator2 = 0
      while iterator2 < len(lines_to_write):
        final.write("%s"%lines_to_write[iterator2])
        iterator2 += 1
      final.close()

    #Empty the lines_to_write list for the next iteration
    while len(lines_to_write)>0:
      lines_to_write.pop()

    iterator += 1
    results_file.close()



#This function calculates the average localization times for each one of the tests
def average_localization_time():
  iterator = 0
  total_sum = 0.0
  meta_data = []
  global maximum_testruns
  #We iterate through the test result files
  while iterator < maximum_testruns:
    results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/loc_results_%d'%iterator,"r")
    #Check each line in the file
    for line in results_file:
      #If there was no detection and localization for a given line, it will be skipped
      if ';;;;;;;;' not in line:
       helper = line.split(';')
       iterator2 = 0
       #Collect the times into a total_sum and store each of the values in a list
       while iterator2 < len(helper):
         if (helper[iterator2] != '') and (helper[iterator2] != "\n"):
           total_sum += float(helper[iterator2])
           meta_data.append(helper[iterator2])
         iterator2 += 1
    #Open the results file and add the detected values
    final = open(FINAL_TEST_RESULTS,"a")
    try:
      average = total_sum / len(meta_data)
    except ZeroDivisionError:
      print "ZeroDivisionError excepted in average localization time calculation. Variable values are the followings:"
      print "Iterator: %d"%iterator
      print "Total sum %.5f"%total_sum

    #In the first iteration we need a name for the row
    if iterator == 0:
      final.write('average_localization;%0.5f'%average)
    #At the last iteration we have to open a new line
    elif iterator == (maximum_testruns - 1):
      final.write(';%0.5f\n'%average)
    else:
      final.write(';%0.5f'%average)
    final.close()
    iterator += 1
    results_file.close()

#This function calculates the median localization times for each one of the tests
def median_localization_time():
  iterator = 0
  meta_data = []
  global maximum_testruns
  #We iterate through the test result files
  while iterator < maximum_testruns:
    results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/loc_results_%d'%iterator,"r")
    #Check each line in the file
    for line in results_file:
      #If there was no detection and localization for a given line, it will be skipped
      if ';;;;;;;;' not in line:
       helper = line.split(';')
       iterator2 = 0
       #We append all the localization times to a list
       while iterator2 < len(helper):
         if (helper[iterator2] != '') and (helper[iterator2] != "\n"):
           meta_data.append(float(helper[iterator2]))
         iterator2 += 1
    iterator2 = 0
    #This section performs a bubble-sort over the list we aquired (not optimal, but works)
    while iterator2 < len(meta_data):
      iterator3 = 0
      while iterator3 < len(meta_data):
        if meta_data[iterator2] > meta_data[iterator3]:
          helper2 = meta_data[iterator2]
          meta_data[iterator2] = meta_data[iterator2]
          meta_data[iterator3] = helper2
        iterator3 += 1
      iterator2 += 1
    #Select the middle value of the now sorted list, and save it as it is the median
    middle_value = len(meta_data)/2
    median = meta_data[middle_value]
    #Append the median value to the results file
    final = open(FINAL_TEST_RESULTS,"a")
    #In the first iteration we need a name for the row
    if iterator == 0:
      final.write('median_localization;%0.5f'%median)
    #At the last iteration we have to open a new line
    elif iterator == (maximum_testruns -1):
      final.write(';%0.5f\n'%median)
    else:
      final.write(';%0.5f'%median)
    final.close()
    iterator += 1
    results_file.close()
    #Empty the meta_data lisst for the next iteration
    while len(meta_data) > 0:
      meta_data.pop()


#This function calculates the average patcher times for each one of the tests
def average_patcher_time():
  iterator = 0
  total_sum = 0.0
  meta_data = []
  global maximum_testruns
  #We iterate through the test result files
  while iterator < maximum_testruns:
    results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/patcher_results_%d'%iterator,"r")
    #Check each line in the file
    for line in results_file:
      #Collect the times into a total_sum and store each of the values in a list
      helper = float(line[:-1])
      total_sum += helper
      meta_data.append(helper)
    #Open the results file and add the detected values
    final = open(FINAL_TEST_RESULTS,"a")
    try:
      average = total_sum / len(meta_data)
    except ZeroDivisionError:
      print "ZeroDivisionError excepted in average localization time calculation. Variable values are the followings:"
      print "Iterator: %d"%iterator
      print "Total sum %.5f"%total_sum
    #In the first iteration we need a name for the row
    if iterator == 0:
      final.write('average patcher time;%0.5f'%average)
    #At the last iteration we have to open a new line
    elif iterator == (maximum_testruns - 1):
      final.write(';%0.5f\n'%average)
    else:
      final.write(';%0.5f'%average)
    final.close()
    iterator += 1
    results_file.close()


#This function calculates the median patcher times for each one of the tests
def median_patcher_time():
  iterator = 0
  meta_data = []
  global maximum_testruns
  #We iterate through the test result files
  while iterator < maximum_testruns:
    results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/patcher_results_%d'%iterator,"r")
    #Check each line in the file
    for line in results_file:
      #Collect the times into a list
      helper = float(line[:-1])
      meta_data.append(helper)
    #Perform bubble-sort on the list
    iterator2 = 0
    while iterator2 < len(meta_data):
      iterator3 = iterator2 + 1
      while iterator3 < len(meta_data):
        if meta_data[iterator2] > meta_data[iterator3]:
          helper = meta_data[iterator2]
          meta_data[iterator2] = meta_data[iterator3]
          meta_data[iterator3] = helper
        iterator3 += 1
      iterator2 += 1
    #Open the results file and add the detected values
    final = open(FINAL_TEST_RESULTS,"a")
    #In the first iteration we need a name for the row
    if iterator == 0:
      final.write('median patcher time;%0.5f'%meta_data[5])
    #At the last iteration we have to open a new line
    elif iterator == (maximum_testruns - 1):
      final.write(';%0.5f\n'%meta_data[5])
    else:
      final.write(';%0.5f'%meta_data[5])
    final.close()
    iterator += 1
    results_file.close()
    #Empty the meta_data lisst for the next iteration
    while len(meta_data) > 0:
      meta_data.pop()

def avg_packets_generated():
  iterator = 0
  meta_data = []
  global maximum_testruns
  line_selector = 1
  while line_selector < 10:
    total_sum = 0.0
    iterator = 0
    #We iterate through the test result files
    while iterator < maximum_testruns:
      results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/packets_generated_%d'%iterator,"r")
      #Check each line in the file
      line_counter = 1
      for line in results_file:
        #Collect the number of packets into a total_sum and store each of the values in a list
        if line_counter == line_selector:
          helper = float(line[:-1])
          total_sum += helper
          meta_data.append(helper)
        line_counter += 1
      iterator += 1
      results_file.close()

    #Open the results file and add the detected values
    final = open(FINAL_TEST_RESULTS,"a")
    try:
      average = total_sum / len(meta_data)
    except ZeroDivisionError:
      print "ZeroDivisionError excepted in average localization time calculation. Variable values are the followings:"
      print "Iterator: %d"%iterator
      print "Total sum %.5f"%total_sum
    #In the first iteration we need a name for the row
    if line_selector == 1:
      final.write('average packets generated;%d'%average)
    #At the last iteration we have to open a new line
    elif line_selector == (maximum_testruns - 1):
      final.write(';%d\n'%average)
    else:
      final.write(';%d'%average)
    final.close()
    line_selector += 1
    #Empty the meta_data lisst for the next iteration
    while len(meta_data) > 0:
      meta_data.pop()


#This function calculates the median number of packets sent for each one of the tests
def median_packets_generated():
  iterator = 0
  meta_data = []
  global maximum_testruns
  line_selector = 1
  while line_selector < maximum_testruns:
    iterator = 0
    #We iterate through the test result files
    while iterator < maximum_testruns:
      results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/packets_generated_%d'%iterator,"r")
      line_counter = 0
      #Check each line in the file
      for line in results_file:
        line_counter += 1
        #Collect the number of packets into a list
        if line_counter == line_selector:
          helper = float(line[:-1])
          meta_data.append(helper)
      iterator += 1
      results_file.close()
    #Perform bubble-sort on the list
    iterator2 = 0
    while iterator2 < len(meta_data):
      iterator3 = iterator2 + 1
      while iterator3 < len(meta_data):
        if meta_data[iterator2] > meta_data[iterator3]:
          helper = meta_data[iterator2]
          meta_data[iterator2] = meta_data[iterator3]
          meta_data[iterator3] = helper
        iterator3 += 1
      iterator2 += 1
    #Open the results file and add the detected values
    final = open(FINAL_TEST_RESULTS,"a")
    #In the first iteration we need a name for the row
    if line_selector == 1:
      final.write('median packets generated;%d'%meta_data[5])
    #At the last iteration we have to open a new line
    elif line_selector == (maximum_testruns - 1):
      final.write(';%d\n'%meta_data[5])
    else:
      final.write(';%d'%meta_data[5])
    final.close()
    line_selector += 1
    #Empty the meta_data lisst for the next iteration
    while len(meta_data) > 0:
      meta_data.pop()

def localization_effectiveness():
  results = 'asd'
  global maximum_testruns
  #We iterate through the test result files
  iterator2 = 0
  while iterator2 < 4:
    iterator = 0
    while iterator < maximum_testruns:
      results_file = open('/home/apoorv/p4rl_tarantula/RL_for_P4/results/automated_results/susp-results_%d'%iterator,"r")
      #Read in the lines of the file
      for line in results_file:
        if iterator2 == 0 and 'true_positives' in line:
          results = line
        elif iterator2 == 1 and 'true_negatives' in line:
          results = line
        elif iterator2 == 2 and 'false_negatives' in line:
          results = line
        elif iterator2 == 3 and 'false_positives' in line:
          results = line

      #Append the results to the final results file
      final = open(FINAL_TEST_RESULTS,"a")
      if iterator == 0:
        final.write('%s;'%results[:-1])
      elif iterator == (maximum_testruns - 1):
        helper = results.split(';')
        final.write('%s'%helper[1])
      else:
        helper = results.split(';')
        final.write('%s;'%helper[1][:-1])
      iterator += 1
    final.close()
    results_file.close()
    iterator2 += 1



def main():
  #First clean the result files of previous tests
  clean_test_results()
  #Collect the detection times of the 10 test runs
  detection_times_collector()
  #Collect the average localization time for the tests
  average_localization_time()
  #Collect the median localization time for the tests
  median_localization_time()
  #Collect the average patcher time for the tests
  average_patcher_time()
  #Collect the median patcher time for the tests
  median_patcher_time()
  #Collect the average packets generated throughout the testcases
  avg_packets_generated()
  #Collect the median packets generated throughout the testcases
  median_packets_generated()
  #Calculate the effectiveness of the localization
  localization_effectiveness()


if __name__ == '__main__':
    main()

