import os
import sys
from collections import deque
from scapy_definitions import return_scapy_definitions, return_scapy_protocol_types

#Defined constants for the program (if environment is changed, these has to be changed too!!!)
HEADER_TYPES_FILE = '/home/apoorv/p4rl_tarantula/RL_for_P4/build/header_types.txt'
OUTPUT_FILE = '/home/apoorv/p4rl_tarantula/RL_for_P4/build/code_reader_output.txt'
HEADERS_PY = '/home/apoorv/p4rl_tarantula/RL_for_P4/build/headers.py'
#Invalid header accesses are not used in the current version
INVALID_ACCESSES_LOG = '/home/apoorv/zsolt-thesis/demo/logs/invalid-accesses.txt'

#Defining the lis of well-known and used header types
def header_list():
  header_types = HEADER_TYPES_FILE
  with open(header_types) as h:
    headers = h.read().splitlines()
  return headers

#Definition to delete all previous data from a file
def DeleteContent(pfile):
  pfile.seek(0)
  pfile.truncate()

#Function to check if a string has numbers or not
def hasNumbers(inputString):
  return any(char.isdigit() for char in inputString)

#This function checks if the system-call contained the source-code
def pre_check():
  print 'Running the P4 code reader component'
  if len(sys.argv)<2:
      print 'Correct usage: p4_code_ready.py <path_to_the_p4_code>'
      exit(1)
  if len(sys.argv)>2:
      print 'Too many arguments!'
      print 'Correct usage: p4_code_ready.py <path_to_the_p4_code>'
      exit(1)

#This function identifies the headers defined in the provided source code
#If there is no existing scapy representation of the header format, this section creates that too
def header_reads(source_code):
  #Calling the header_list function
  header_types = header_list()
  #Open the source code
  original_file = open(source_code)
  #Creatig a helper variable to store the mid-process header names
  header_helper = 'begin'
  #Creating the list variable to store the actually defined headers
  headers = list()
  #Create a variable to store the value of the previous line
  previous_line = 'empty'

  #Checking for defined header types in the code
  for line in original_file:
    #the last condition is needed to avoid collecting informations from header defining stuctures (like in the translated version of switch.p4)
    if 'header' in line  and '_t '  in line and '(' not in line and ')' not in line and '=' not in line and '@name' not in previous_line:
      header_helper = line
      header_helper = header_helper.strip(' ')
      end_position = header_helper.rfind('_t ')
      header_helper = header_helper[7:end_position]
      headers.append(header_helper)
    #Check a second version, where each header has a defined name in the P4 source code too
    elif 'header' in line and '_t' in line and '@name' in line and '(' in line and ')' in line and '<' not in line and '>' not in line and 'action' not in line:
      header_helper_basic = line.split(')')
      header_helper = header_helper_basic[1].strip(' ')
      end_position = header_helper.rfind('_t')
      header_helper = header_helper[7:end_position]
      headers.append(header_helper)
    previous_line = line
  #Closing the P4 code file
  original_file.close()

  #Visual check for the found headers
  #print headers

  #Opening the output file
  output = open(OUTPUT_FILE, "wt")
  #Comparing the existing headers with the predefined list
  for index in range (0, len(headers)):
    found = headers[index] in header_types
    if found:
      #As it was found in the already defined list, we just write it out and move to the next one
      output.write(headers[index] + '\n')
    else:
      #Re-opening the original file to find the private header
      original_file = open(source_code)
      #print 'Header was not found in the pre-defined list, handled as a private header'
      head = open(HEADERS_PY, "a")
      #Write the initial parts required in the header definition file
      head.write('\nclass %s(Packet):' %headers[index] + '\n')
      head.write('  name = "%s"' %headers[index]+ '\n')
      head.write('  fields_desc = [ ')

      #Define two deciders for later usage
      decider = 'false'
      first_line = 'true'
      #Lets look for the header again in the source code and add its scapy definition to our .py file
      for line in original_file:
        #Check to read only required ammount of data
        # if the header was found and the header keyword appears again in the line
        # we can safely assume that we have finished defining the private header-type
        if (decider == 'true') and 'header' in line:
          decider = 'false'
        if 'bit' in line and (decider =='true') and '@name' not in line:
          intermediate_result = line
          #Remove the spaces in the line, so we can get the field name easier
          intermediate_result = intermediate_result.replace(' ', '')
          #We can safely assume that every header field is less then 1000 bites long
          #So checking on 3 different positions in the line is enough
          bit_left   = intermediate_result.index("<")
          bit_right  = intermediate_result.index(">")
          row_ending = intermediate_result.index(";")
          #Defining the length variable, and getting the name of the header-field
          length = intermediate_result[bit_left+1:bit_right]
          name = intermediate_result[bit_right+1:row_ending]
          #Handling the case where the length of the header is defined by a constant variable
          try:
            length = int(length)
          except ValueError:
            #Helper variable to hit only one line
            value_found = False
            #Reset to the beginning of the source code
            original_file.seek(0)
            #Set the length variable back to the correct value
            length = intermediate_result[bit_left+1:bit_right]
            #If it was not an integer, we look through the source code again to find the definition
            for line2 in original_file:
              if length in line2 and 'define' in line2 and value_found is False:
                length = line2[-5:-1].lstrip(' ')
                value_found = True
              #When we hit the current line, we leave this cycle
              if line in line2:
                break
          #Writing out the lines to the class definition
          if first_line == 'false':
            head.write(',\n' + '                  ' + 'BitField("%s", 0, %s)' %(name, length))
          if first_line == 'true':
            first_line = 'false'
            head.write('BitField("%s", 0, %s)' %(name, length))
        #If the name of the private header appears, we ASSUME that the definition of it follows
        if '%s' %headers[index]  in line and (first_line == 'true'):
          decider = 'true'
      #Before closing, the packet definition has to be cloased
      head.write(']\n')
      #Writing out the now defined header type to the valid headers list
      output.write(headers[index] + '\n')
      #To avoid multiple times defining the same header, add it to our header list
      header_types_file_we_use = open(HEADER_TYPES_FILE, "a")
      header_types_file_we_use.write(headers[index] + '\n')
      header_types_file_we_use.close()
      #Closing the P4 code file
      original_file.close()

      #Now that we have the packet definition, we need to bind it to the correct spot
      #Re-opening the original file to find the private header
      original_file = open(source_code)
      #Variable to get only one line as a result
      found_it = 'false'
      #Variable to see if the select statement was available in the last few, stored lines
      select_found = 'false'
      #Fixed length list to store the last few lines - it will be needed to determine which value has to be fixed
      previous_lines = deque(maxlen=5)
      for line in original_file:
        if 'parse_%s' % headers[index] in line and (found_it == 'false'):
          intermediary = line
          intermediary = intermediary.replace(' ','')
          intermediary = intermediary[0:len(intermediary)-len(headers[index])-9]
          found_it = 'true'
          #Check if it contains numbers (we assume it is correct in this case)
          #If not, we have to look for a definition containing our code
          if hasNumbers(intermediary):
            #iterate through the previous lines
            for element in previous_lines:
              if 'transition select' in element:
                #Set the select_found variable to true --> we have found what we were looking for
                select_found = 'true'
                #After the select statement was found format the output
                second_intermediary = element
                second_intermediary = second_intermediary.replace(' ','')
                second_intermediary = second_intermediary[21:len(second_intermediary)-3]
                #Split the result string into to, e.g. ethernet.etherType --> ethernet, etherType
                results = second_intermediary.split('.',1)
                #Writing out the bind statement to the packet defining python file
                head.write('\nclass binding_%s():'%headers[index])
                head.write('\n  bind_layers(' + return_scapy_definitions(results[0])[0:len(return_scapy_definitions(results[0]))-3]  + ', ' + headers[index] + ', ' + return_scapy_protocol_types(results[1]) + '=' + intermediary + ')\n')
          else:
            #print 'The found version has no numbers, have to look for the definition'
            #Helper variable to hit only one line
            value_found = False
            #Reset to the beginning of the source code
            original_file.seek(0)
            #We need to store the value of the previous line for a case if our parsing is the default value
            previous_line = 'empty'
            #If it was not an integer, we look through the source code again to find the definition
            for line2 in original_file:
              #If it is mapped as a default value, we extract an other option and the value corresponding to it
              #Than change this value around, so we can create a mapping on a different (unused) value
              if intermediary == 'default' and headers[index] in line2 and intermediary in line2:
                previous_line = previous_line.lstrip(' ')
                helper = previous_line.split(':')
                #Exctract a mapping value from the previous line
                if '16w0x' in previous_line:
                  intermediary = helper[0][3:]
                  value_found = True
                elif '8w0x' in line2:
                  intermediary = helper[0][2:]
                  value_found = True
                 #Now that we have another value, time to change it
                if value_found is True:
                  changing_value = int(intermediary[-1])
                  changing_value += 1
                  intermediary = intermediary[:-1] + str(changing_value)
              if intermediary  in line2 and 'define' in line2 and value_found is False:
                if '16w0x' in line2:
                  intermediary = line2[-5:-1].lstrip(' ')
                elif '8w0x' in line2:
                  intermediary = line2[-3:-1].lstrip(' ')
                value_found = True
              #Store the current line before moving on
              previous_line = line2
              #When we hit the current line, we leave this cycle
              if line in line2:
                break
            #iterate through the previous lines
            for element in previous_lines:
              if 'transition select' in element:
                #Set the select_found variable to true --> we have found what we were looking for
                select_found = 'true'
                #After the select statement was found format the output
                second_intermediary = element
                second_intermediary = second_intermediary.replace(' ','')
                second_intermediary = second_intermediary[19:len(second_intermediary)-3]
                #Split the result string into to, e.g. ethernet.etherType --> ethernet, etherType
                results = second_intermediary.split('.')
                #Writing out the bind statement to the packet defining python file
                head.write('\nclass binding_%s():'%headers[index])
                head.write('\n  bind_layers(' + return_scapy_definitions(results[len(results)-2])[0:len(return_scapy_definitions(results[len(results)-2]))-3]  + ', ' + headers[index] + ', ' + return_scapy_protocol_types(results[len(results)-1]) + '=' + intermediary + ')\n')

        else:
          previous_lines.append(line)
      #Closing the P4 code file
      original_file.close()
      #Closing the headers file
      head.close()
      #Notify the user about that the program was not able to detect the parsing for the uniquely defined header
      if select_found == 'false':
        print '*****************************'
        print 'The compiler was not able to find the parser statement for the unique header. This way it was not able to make the binding statement. \nPlease consider increasing the number of the maximum length of the dequeue!'
        print '*****************************'


  #Closing the output file
  output.close()


#This function implements a check to find if any headers are accessed correctly in the source code
#NOT USED IN THE CURRENT VERSION
def invalid_header_accesses(source_code):
  #Open the source code
  original_file = open(source_code,"r")
  #Create a list to store the headers that get changed in the P4 code
  headers_changing = []
  #Create a list for the actions and tables in correlation to the headers
  corresponding_actions = []
  corresponding_tables  = []
  #Create a list to store the last 5 lines of the code
  previous_lines = []
  #Create a boolean to store if the validity check was found or not
  validity_check_found = False
  line_resulting_in_validity_error = 'empty'
  #Read through the file line-by-line
  for line in original_file:
    #Check if a header's value getting changed - except for ethernet, as we take it for granted that will appear in most of the p4 source codes
    #TODO: metadata condition can cause errors to go undetected, change it maybe later to multiple different options (e.g. intrinsic_metadata, egress_metadata, etc.)
    if 'hdr.' in line and  'ethernet' not in line and ('=' in line or 'exact' in line or 'ternary' in line or 'lmp' in line) and 'intrinsic_metadata' not in line and 'ingress_metadata' not in line and 'egress_metada' not in line and 'egress_spec' not in line:
      helper = line.split('.')
      #Prevent to add a header-type multiple times
      if 'hdr' in helper[1]:
        helper[1] = helper[1].replace(' ','')
        helper[1] = helper[1][:-4]
      if helper[1] not in headers_changing:
        headers_changing.append(helper[1])
  #As long as we have affected headers, we are looking for the invalid accesses
  while len(headers_changing) > 0:
    #Go back to the beginning of the source code
    original_file.seek(0)
    #Set up an iterator, to shorten parts of the code
    it = len(headers_changing) - 1
    #Look for the line where the change happens
    for line in original_file:
      if 'hdr.' in line and headers_changing[it] in line and ('=' in line or 'exact' in line or 'ternary' in line or 'lmp' in line):
        #Now check for the action executing the change, or the match condition
        iterator = 0
        while iterator < 5:
          #The change is triggered by an action
          if 'action' in previous_lines[iterator] and '{' in previous_lines[iterator]:
            helper = previous_lines[iterator].replace(' ','')
            if '@name' in previous_lines[iterator]:
              helper2 = helper.split(')')
              helper3 = helper2[1].split('(')
              corresponding_actions.append(helper3[0][6:])
            else:
              helper = helper[6:]
              helper2 = helper.split('(')
              corresponding_actions.append(helper2[0])
          #The header is accessed by a match condition of a table
          if 'table' in previous_lines[iterator] and '{' in previous_lines[iterator]:
            helper = previous_lines[iterator].replace(' ','')
            if '@name' in previous_lines[iterator]:
              helper2 = helper.split(')')
              corresponding_actions.append(helper2[1][5:-2])
            else:
              corresponding_tables.append(helper[5:-2])

          iterator += 1
      #Maintain the previous lines list, to only contain up to 5 lines
      if len(previous_lines) == 5:
        iterator = 0
        while iterator < 4:
          previous_lines[iterator] = previous_lines[iterator+1]
          iterator += 1
          previous_lines.pop()
          previous_lines.append(line)
      else:
        previous_lines.append(line)
    #If the header was accessed by an action, we have to find the corresponding table
    while len(corresponding_actions) > 0:
      #Empty the previous_lines list
      while len(previous_lines) > 0:
        previous_lines.pop()
      #Set iterator to ease implementation
      i = len(corresponding_actions) - 1
      #Go back to the beginning of the file
      original_file.seek(0)
      #Look the whole thing through again for the tables corresponding to the actions
      for line in original_file:
        if ';' in line and corresponding_actions[i] in line: #TODO: potential error source for bigger codebases
          iterator = 0
          while iterator < 10:
            if 'table' in previous_lines[iterator] and '{' in previous_lines[iterator]:
              helper = previous_lines[iterator].replace(' ','')
              if '@name' in previous_lines[iterator]:
                helper2 = helper.split(')')
                corresponding_tables.append(helper2[1][5:-2])
              else:
                helper = helper[5:-2]
                corresponding_tables.append(helper)
            iterator += 1
        #Maintain the previous lines list, to only contain up to 5 lines
        if len(previous_lines) == 10:
          iterator = 0
          while iterator < 9:
            previous_lines[iterator] = previous_lines[iterator+1]
            iterator += 1
            previous_lines.pop()
            previous_lines.append(line)
        else:
          previous_lines.append(line)

      corresponding_actions.pop()
    #Now we finally have the tables accessing the header fields
    #As a next step we should look for the application of these tables, and if there is a check before or not
    #As a start, empty the previous_lines and reset the source_code to the beginning
    original_file.seek(0)
    while len(previous_lines)>0:
      previous_lines.pop()
    while len(corresponding_tables)>0:
      #Now start looking through the file
      for line in original_file:
        if corresponding_tables[len(corresponding_tables)-1] in line and '.apply()' in line:
          iterator = 0
          line_resulting_in_validity_error = line.lstrip(' ')
          line_resulting_in_validity_error = line_resulting_in_validity_error[:-1]
          while iterator < 5:
            if 'hdr.%s.isValid()'%headers_changing[it] in previous_lines[iterator]:
              validity_check_found = True
              line_resulting_in_validity_error = 'empty'
            iterator += 1
        #Maintain the previous lines list, to only contain up to 5 lines
        if len(previous_lines) == 5:
          iterator = 0
          while iterator < 4:
            previous_lines[iterator] = previous_lines[iterator+1]
            iterator += 1
            previous_lines.pop()
            previous_lines.append(line)
        else:
          previous_lines.append(line)
      corresponding_tables.pop()
    if validity_check_found is False:
      log_file = open(INVALID_ACCESSES_LOG,"a")
      log_file.write("Header(%s) accessed without pre-check by the table referenced in the following line of code: %s\n"%(headers_changing[-1],line_resulting_in_validity_error))
      log_file.close()
      #print 'ERROR - INVALID HEADER ACCESS'
    validity_check_found = False
    #Before moving on, empty both side-lists - they should be empty already, just as a make-sure step
    while len(corresponding_actions)>0:
      corresponding_actions.pop()
    while len(corresponding_tables)>0:
      corresponding_tables.pop()
    #Pop the header for which we have found if there is an invalid access
    headers_changing.pop()
  #TODO list:
    #ha megvan a tabla, akkor meg lehet nezni, hogy az alkalmazasa elott van-e check
  #Close the source code
  original_file.close()

def main():

  #Delete the results of previous runs
  file = open(OUTPUT_FILE,"w")
  file.close()
  file = open(INVALID_ACCESSES_LOG,"w")
  file.close()
  #Check if the system-call contains the source-code
  pre_check()

  #Taking the first argument as the path to the P4 code, and opening it
  file_path = sys.argv[1]
  #Call the function responsible to identify and write out the headers in the given source code
  header_reads(file_path)
  #Call the static analysis function to find invalid header accesses
  #invalid_header_accesses(file_path)

if __name__ == '__main__':
    main()

