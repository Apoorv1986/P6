#!/vagrant/controller_venv/bin/python
import sys
import os
import time


#Initialization of global variables
RESULTS_FILE = str(sys.argv[1])  #Taken as an argument, the script uses this to determine the location of the file containing the results (decisions) of the packets sent in the testcase
P4_SOURCE_CODE = '/vagrant/run_files/actual.p4'
LOCALIZATION_RESULTS = '/vagrant/logs/localization-results.txt'
testcase_results = []           #The script stores the lines of the results file in this variable
source_code_lines_dict = {}     #The script stores the lines of the lines of the dirctionary in this variable
source_code_lines = []          #The script stores the liens of the source code in this variable
totalFailed = 0                 #The script uses this integer to measure how many packets were determined as failed in the results
totalPassed = 0                 #The script uses this integer to measure how many packets were determined as passed in the results
start_time = float(sys.argv[2]) #Received as an argument, so we can measure how much time did it take to run the patcher component


#This class defines the native attributes of a line of the source code
class P4_code_line:
        def __init__(self, score=0.0, text= "", lineNo=0, localization_time=100000.0):
                self.score = score
                self.text = text
                self.lineNo = lineNo
                self.localization_time = localization_time
        #Score contains the suspeciousness score
        def setScore(self, score):
                self.score = score
        #Text contains the limne of code itself
        def setText(self, text):
                self.text = text
        #LineNO contains the number of the line (e.g. 55th line of the code)
        def setLineNo(self,lineNo):
                self.lineNo = lineNo
        #localization times contains the time it was run through the localization (starting from the envocation of the P4Tarantula component)
        def setLocalization_time(self, localization_time):
                self.localization_time = localization_time
        #Definition on how to use > comparison between two lines
        #Saying that a line is considered bigger, if the suspiciousness score of that line is bigger
        def __gt__(self, line2):
                return self.score > line2.score


#This class defines the basic attributes for the lines of the results file
class results_line:
  def __init__(self, pkt='empty', passed=True, error_type='passed'):
    self.pkt = pkt
    self.passed = passed
    self.error_type = error_type
  #pkt variable identifies the scapy definition of the sent packet
  def setPkt(self, pkt):
    self.pkt = pkt
  #Passed is a boolean variable determining if the given packet was considered faulty of not (passed=True means there were no errors)
  def setpassed(self, passed):
    self.passed = passed
  #Error_type contains the decision about what type of error was identified (the default passed means there were no errors detected with the packet)
  def setError_type(self, error_type):
    self.error_type = error_type

#This function empties the localization results file
def clear_localization_results():
  results = open(LOCALIZATION_RESULTS,"w")
  results.close()


#This function reads the output provided to the testcase_results file
#And imports it into variables in a stack
def results_read_in():
  #Calling the global variables
  global testcase_results
  global totalFailed
  global totalPassed

  #Opens the file
  results_file = open(RESULTS_FILE)

  #Checks every line for packet numbers, and the result of the test
  #Also increases global counters for total failed and passed test cases
  for line in results_file:
    line = line.strip().split(';')
    if line[0] == 'F\n' or line[0] == 'F'  or line[0] == 'f\n'  or line[0] == 'f' :
      totalFailed += 1
      helper = results_line(line[2],False,line[1])
      testcase_results.append(helper)
    if line[0] == 'P\n' or line[0] == 'P' or line[0] == 'p\n' or line[0] == 'p'  :
      totalPassed += 1
      helper = results_line(line[2],True,line[1])
      testcase_results.append(helper)
  #Closes the results file
  results_file.close()

#This functions imports the source code into a stack
def source_code_read_in():

  #Open up the original source code
  source_code = open(P4_SOURCE_CODE,"r")

  #Iterate through the source code and read in every line
  iterator = 1
  for line in source_code:
    helper = P4_code_line(0.0,line,iterator)
    iterator += 1
    source_code_lines.append(helper)
  #Closing the used file
  source_code.close()

#This function creates a dictionary from the source-code stack
def create_source_code_dict():

  global source_code_lines_dict
  iterator = 0
  #Fill up the dictionary with starting values: every line was executed 0 times in passes, 0 times in fails
  while iterator < len(source_code_lines):
    iterator += 1
    source_code_lines_dict[iterator] = [0.0,0.0]

#This function helps to keep counting how many times a single line was executed
def execution_counter(lineno,passed):
  global source_code_lines_dict
  for key in source_code_lines_dict.keys():
    if lineno == key:
      helper = source_code_lines_dict[lineno]
      if passed is True:
        helper[0] += 1.0
      else:
        helper[1] += 1.0
      source_code_lines_dict[lineno] = helper


#This functions check which lines were executed by a given packet
#Black magic
def trace(result):

  #Open the P4 source code
  source_code = open(P4_SOURCE_CODE,"r")

  pkt = result.pkt               #This variable stores the packet that was used to trigger the bug
  error_type = result.error_type #This variable stores what type of error was identified in the detection
  passed = result.passed         #This variable stores if the current packet was a failed or a passed packet according to our detection
  packet_headers = []            #This variable stores the packet headers used in the packet sent
  tables_found = []              #This variable stores the different tables identified in the source_code
  actions_to_look_for = []       #This variable stores the actions corresponding to the actually investigated table
  have_been_checked = False      #This variable is used to determine if the function has found the error cause already
  last_table = False             #This variable is set to True when the function investigates the last table from the tables_found list
  ingress = True                 #This variable is used to determine if the execution of the packet is in the first half(ingress), or the second half (egress) of the execution path
  error_found = False            #This variable is used to determine if the function has found a suspicious line
  global  source_code_lines
  #Gather what type of headers are defined in the packet
  #Note that our prototype implementation only works with ethernet and IP, does not takes other headers into account
  if 'Ether' in pkt:
    packet_headers.append('ethernet')
  if 'IP' in pkt:
    packet_headers.append('ipv4')

  #The execution of the P4 program starts at the following line
  #We use this variable to "move around" in the source code
  next_line_to_look_for = 'state start {'

  line_counter = 1
  #Now we  start following the packet through the P4 code
  for line in source_code:
    #The following if and elif statements identifies if an error in the current line is existing,
    #based on the errors reported by the detection mechanism
    #The error_type variable stores the value of what error was picked up by the detector, while the rest of the conditions look for typical parts of the code
    if (error_type == 'ttl' or error_type == 'ttl_1') and (('ttl' in line and '-' in line and '1' in line) or ('ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line)):
      error_found = True
    elif error_type == 'version'  and 'ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line and 'version' not in line:
      error_found = True
    elif (error_type == 'chksum' or error_type == 'chksum_e')  and 'control' in line and 'inout headers' in line and 'inout metadata' in line and ('verify' in line or 'Verify' in line) and ('checksum' in line or 'chksum' in line or 'Checksum' in line):
      if source_code_lines[line_counter-1].score == 0:
        source_code_lines[line_counter-1].setScore(1.0)
        source_code_lines[line_counter].setScore(1.0)
        #Set the lines detection time
        source_code_lines[line_counter-1].setLocalization_time(time.time() - start_time)
        source_code_lines[line_counter].setLocalization_time(time.time() - start_time)
    elif error_type == 'ihl' and 'ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line and 'ihl' not in line:
      error_found = True
    elif error_type == 'len' and 'ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line and 'ihl' not in line and 'totalLen' not in line:
      error_found = True
    elif error_type == 'mac_swap':
      print "This patch was not implemented, as we have not found any of this type of bug in the tested applications"
    elif error_type == 'port' and 'standard_metadata' in line and 'egress_spec' in line and '=' in line:
      error_found = True
    elif error_type == 'dst_mac' and 'hdr' in line and ( 'ethernet' in line or 'eth' in line or 'Ethernet' in line or 'ether' in line) and '=' in line and ('dstAddr' in line or 'destination' in line or 'dst' in line):
      error_found = True

    #If we have found any suspicious lien of code, we execute the following few lines to set the suspiciousness score to 1.0
    if error_found is True:
      error_found = False
      if source_code_lines[line_counter-1].score == 0.0:
        source_code_lines[line_counter-1].setScore(1.0)
        #Set the lines detection time
        source_code_lines[line_counter-1].setLocalization_time(time.time() - start_time)

    #Increase the line_counter to be inline with the actual line
    line_counter += 1
    if next_line_to_look_for in line:
      #Move to the next line, as it is the next one to be executed after the one we were looking for - with 'some' exceptions
      if next_line_to_look_for != 'Ingress' and next_line_to_look_for != 'apply {' and next_line_to_look_for != 'apply()' and 'table' not in line and 'action' not in line and have_been_checked is False:
        execution_counter(line_counter,passed)
        line = source_code.next()
        #Set the lines detection time
        source_code_lines[line_counter-1].setLocalization_time(time.time() - start_time)
        line_counter += 1

      #Check for header extractions - note that our prototye do not checks for errors in this stage
      if '.extract' in line:
        execution_counter(line_counter,passed)
        line = source_code.next()
        #Set the lines detection time
        source_code_lines[line_counter-1].setLocalization_time(time.time() - start_time)
        line_counter += 1
      #Check if the line moves to the next parser state
      if 'transition' in line:
        #If a select statement is there, the tracing have to continue to the correct state
        if 'transition select' in line:
          #Move to the first line of the select statement
          execution_counter(line_counter,passed)
          line = source_code.next()
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)
          if 'ipv4' in packet_headers and 'ipv4' in line:
            #Collect the parsing state it would go to
            helper = line.split(":")
            next_line_to_look_for = helper[1][:-2]
            next_line_to_look_for = next_line_to_look_for.lstrip(' ')
            #Move back to the first line of the file and reset the line counter
            source_code.seek(0)
            line_counter = 1
        #With transition accept, the program jumps to the next execution phase, the match-action pipeline
        elif 'transition accept' in line:
          next_line_to_look_for = 'Ingress'
        #The case with the highest probability, that we only parse for ethernet
        elif 'transition'  in line and 'ethernet' in line:
          line = line.lstrip(' ')
          next_line_to_look_for = line[11:-2]
          next_line_to_look_for = next_line_to_look_for.rstrip(' ')
          #Remove the ethernet header from the list
          if 'ethernet' in packet_headers:
            packet_headers.remove('ethernet')

        #In the rest of the cases, a visual check is implemented to see that something went south
        else:
          print 'Something went south - we have not programmed this path yet'

      #When we find the line starting the ingress match-action pipeline, we move to the "end" of it, to the apply statement
      if 'control' in line and 'Ingress' in line:
        next_line_to_look_for = 'apply {'
      #This sections executes when we found the apply block of the ingress match-action pipeline
      if 'apply {' in line:
        #If the } symbol is also in the line, that meanse an empty apply block
        if '}' not in line:
          #Check for apply statements that indicate which tables are used
          next_line_to_look_for = 'apply()'
          helper = source_code.next()
        #As the execution of ingress finished here, we can move on the the egress part
        elif ingress is True:
          next_line_to_look_for = 'Egress'
        #As the apply statement is used in multiple sections, after the egress match-action pipeline is finished, we move to the deparser based on this
        elif ingress is False:
          next_line_to_look_for = 'Deparser'

        #If it do not apply a table, and it is not an empty block, we simply move to the next line, as it is the next one getting executed
        if 'apply()' not in helper and '}' not in line and have_been_checked is False:
          execution_counter(line_counter,passed)
          line = helper
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)

      #We check the table found
      if 'apply()' in line and last_table is False:
        helper = line.split('.')
        #Tkae the name of the table
        helper[0] = helper[0].lstrip(' ')
        execution_counter(line_counter,passed)
        #Set the lines detection time
        source_code_lines[line_counter-1].setLocalization_time(time.time() - start_time)

        #If the found table was not in our list yet, we add it and perform a check
        if helper[0] not in tables_found:
          next_line_to_look_for = helper[0]
          tables_found.append(next_line_to_look_for)
          have_been_checked = False
          #Move back to the first line of the file and reset the line counter
          source_code.seek(0)
          line_counter = 1
        else:
          #Check if it was the last table applied
          apply_found = False
          #Go through the following 10 lines, checkign for any apply statement
          iterator = 0
          while iterator < 10:
            if 'apply()' in source_code.next() and ingress is True: #As there is no egress processing in the basic.p4, the second part is needed to get to the deparser
              #When an apply statement is found, we set the variable to True, assuming it is still an ingress table
              apply_found = True
            iterator += 1
          #If there were no apply statements found, we assume that it is the last table in the ingress processing, so we can move forward to the egress processing
          if apply_found is False:
            last_table = True
            #As the execution of ingress finished here, we can move on the the egress part
            if ingress is True:
              next_line_to_look_for = 'Egress'
            #As the apply statement is used in multiple sections, after the egress match-action pipeline is finished, we move to the deparser based on this
            else:
              next_line_to_look_for = 'Deparser'
            ingress = False
            #Move back to the first line of the file and reset the line counter
            source_code.seek(0)
            line_counter = 1


      #Move to egress processing
      if 'control' in line and 'Egress' in line:
        next_line_to_look_for = 'apply {'
        last_table = False

      #Check deparsing processing, as the closing state
      if 'control' in line and 'Deparser' in line:
        while '}' not in line:
          execution_counter(line_counter,passed)
          line = source_code.next()
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)

      #The code has arrived to a table - look for the actions, and as fault-localization don't know which path was taken, check all of them
      if 'table' in line:
        while 'actions' not in line:
          execution_counter(line_counter,passed)
          line = source_code.next()
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)
        #Move past the actions line
        execution_counter(line_counter,passed)
        line = source_code.next()
        line_counter += 1
        #Set the lines detection time
        source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)
        while '}' not in line:
          helper = line
          #Format the line to get the correct action name
          helper = helper.lstrip(' ')
          helper = helper[:-2]
          #Collect all the actions into a list - except for NoAction, as it is the default by any P4 device
          if 'NoAction' not in helper:
            actions_to_look_for.append(helper)
          execution_counter(line_counter,passed)
          line = source_code.next()
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)
        #Finish the table (optional size and default action values)
        if line.count('}') == 1:
          #First move up one line
          execution_counter(line_counter,passed)
          line = source_code.next()
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)
          #Finish the table (optional size and default action values)
          while '}' not in line:
            execution_counter(line_counter,passed)
            line = source_code.next()
            line_counter += 1
            #Set the lines detection time
            source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)

        next_line_to_look_for = actions_to_look_for[len(actions_to_look_for)-1]
        #Move back to the first line of the file and reset the line counter
        source_code.seek(0)
        line_counter = 1

      #When we arrive back to the action call, we have to remove it from our list, and invoke the search for the next action
      if 'action' in line:
        actions_to_look_for.pop()
        if len(actions_to_look_for) > 0 :
          next_line_to_look_for = actions_to_look_for[len(actions_to_look_for)-1]
        #If there are no more actions, and we are still in the Ingress phase, we move the trace back to the apply statement of Ingress (with a little re-routing later)
        elif ingress is True and len(actions_to_look_for) == 0:
          next_line_to_look_for = 'Ingress'
          have_been_checked = True
        #If there are no more actions, and we are in the Egress phase, we move the trace back to the apply statement of Egress (with a little re-routing later)
        elif ingress is False and len(actions_to_look_for) == 0:
          next_line_to_look_for = 'Egress'
          have_been_checked = True
        #As the following lines will be executed, set their scores and their localization times
        while '}' not in line:
          execution_counter(line_counter,passed)
          line = source_code.next()
          line_counter += 1
          #Set the lines detection time
          source_code_lines[line_counter-2].setLocalization_time(time.time() - start_time)

        #Move back to the first line of the file and reset the line counter
        source_code.seek(0)
        line_counter = 1

  #Closing the used files
  source_code.close()

#This function calculates the suspiciousness score for every line
def calculate_suspiciousness_score():
  iterator = 0
  #First we iterate through all the lines
  while iterator < len(source_code_lines):
    iterator += 1
    #As a second step, we get how many times a line were executed by passed and failed tests
    if iterator in source_code_lines_dict.keys():
      helper = source_code_lines_dict[iterator]
      #Check if the given line was executed or not
      additional_helper = helper[0] + helper[1]
      if additional_helper != 0 and source_code_lines[iterator-1].score == 0.0:
        #The line was executed, and all the tests have failed --> suspiciousness score is 1
        if totalFailed != 0 and totalPassed == 0:
          suspiciousness_score = 1.0
          source_code_lines[iterator-1].setScore(suspiciousness_score)
        #The line was executed, and all the tests have passed --> suspiciousness score is 0
        if totalFailed == 0 and totalPassed != 0:
          suspiciousness_score = 0.0
          source_code_lines[iterator-1].setScore(suspiciousness_score)
        #The line was executed, and there is a mix of passed and failed tests
        if totalFailed != 0 and totalPassed != 0:
          suspiciousness_score = (helper[1]/totalFailed) / ((helper[0]/totalPassed) + (helper[1]/totalFailed))
          source_code_lines[iterator-1].setScore(suspiciousness_score)


#This function uses bubble sorting to sort the lines in a decreasing order based on their suspiciousnes score
def sorting_results():
  global source_code_lines
  for iterator1 in range(len(source_code_lines)):
    for iterator2 in range(iterator1, len(source_code_lines)):
      if source_code_lines[iterator1] < source_code_lines[iterator2]:
        helper = source_code_lines[iterator1]
        source_code_lines[iterator1] = source_code_lines[iterator2]
        source_code_lines[iterator2] = helper



#This fucntion exports out every line in a file in decreasing order based on their suspeciousness score
def export_results_to_file():
  results = open(LOCALIZATION_RESULTS, "at+")

  #The following lines of code write out every line of the source code to the file
  for iterator in range(len(source_code_lines)):
    results.write('Localization time: %.5f; Number of the line: %d; Suspiciousness: %.2f; Line: %s' %(source_code_lines[iterator].localization_time,source_code_lines[iterator].lineNo,source_code_lines[iterator].score,source_code_lines[iterator].text))

  #Close the file
  results.close()


#This functions evokes the patcher module
def patcher():
  patcher_start_time = time.time()
  os.system("/vagrant/build/patcher.py %s /vagrant/build/patch.p4 2 %s %.5f" %(P4_SOURCE_CODE,LOCALIZATION_RESULTS,patcher_start_time))


def main():
  #Clean the results of previous localization efforts
  clear_localization_results()
  #Read in the results given by the evaluator
  results_read_in()
  #Read in the lines of the source code to a variable
  source_code_read_in()
  create_source_code_dict()
  #Check which lines were run by a given packet
  #Iterate through all the results gathered earlier
  iterator = 0
  while iterator < len(testcase_results):
    #Trace which lines are executed by the given packet
    trace(testcase_results[iterator])
    iterator += 1
  #Based on the results from the traces, we calculate the suspiciousness score for every line
  calculate_suspiciousness_score()

  #The results needs to be ordered in a decreasing order, based on suspiciousness
  sorting_results()

  print "Tarantula was executed succesfully"
  #Write out all the results in a file
  export_results_to_file()

  #Call the patcher part
  patcher()

if __name__ == '__main__':
    main()

