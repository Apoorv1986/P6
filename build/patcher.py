#!/vagrant/controller_venv/bin/python
import sys
import os
import time

#Initialization of global variables
ORIGINAL_FILE = str(sys.argv[1])
PATCHED_FILE = str(sys.argv[2])
#Commented out pathes were used to test the script on the host machine, while the currently active ones are used when running the patcher on the vagrant machine
CODE_READER_OUTPUT = '/vagrant/build/code_reader_output.txt' # '/home/apoorv/p4rl_tarantula/RL_for_P4/build/code_reader_output.txt'
PATCHER_LOG = '/vagrant/logs/patcher_execution_times.txt'    # '/home/apoorv/p4rl_tarantula/RL_for_P4/logs/patcher_execution_times.txt'
header_types = []         #We store the headers defined in the source code in this variable
patch = []                #Later we store the patch to be applied in this variable
localization_results = [] #The script stores the suspicious lines received from the P4Tarantula component
additional_lines = 0      #The script stores as an integer variable, with how many lines it is going to increase the size of the source code
ipv4 = 'empty'            #The script stores in this variable how the ipv4 field is called in the source code
ipv4_fields = []          #The script stores the names defined in the P4 source code for the ipv4 header fields
start_time = float(sys.argv[5]) #Received as an argument, so we can measure how much time did it take to run the patcher component

#This function reads in the header types from the code reader's output
def collect_header_types():
  global header_types
  #We collect the code reader components output
  types = open(CODE_READER_OUTPUT,"r")
  for line in types:
    header_types.append(line)
  #Close the file
  types.close()

#This function collects the ipv4 header_fields defined in the source code
def ipv4_header_fields():
  global ipv4_fields
  #Open up the file
  origi = open(ORIGINAL_FILE,"r")
  #As we have the ipv4 header definitions name, look for it in the file
  for line in origi:
    if '%s'%ipv4 in line and 'header' in line and '_t' in line:
      iterator = 0
      #After finding the ipv4 header definition, we assume that the RFC is followed, and 12 different header fields are defined
      while iterator < 12:
        line = origi.next()
        #We split the lines, and format the name of the header fields for later usage
        if '>' in line:
          helper = line.split('>')
          helper2 = helper[1].lstrip()
          ipv4_fields.append(helper2[:-2])
        elif '_t' in line:
          helper = line.split('_t')
          helper2 = helper[1].lstrip()
          ipv4_fields.append(helper2[:-2])
        else:
          print "Something went south. This error message should never appear, however, it will not effect normal operation. Check P4 source code"
        iterator += 1
  origi.close()

#This function copies the source code to the patcher file
def copy_original_to_patch():
  global patch
  #First open the original file
  origi = open(ORIGINAL_FILE,"r")
  patch = origi.readlines()
  #Close the file
  origi.close()



#This functions fixes the if function focusing on to validate the IPv4 header
def patch_single_line(line_number):
  global additional_lines
  global patch
  #We take the line from the patch list for modifications
  line = patch[line_number]
  #print line
  #The first three conditions evaluates the lines containing ip.isValid
  if ('ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line) and ipv4_fields[7] not in line:
    line = line[:-4] + ' && (hdr.%s.%s > 1)) {\n'%(ipv4,ipv4_fields[7])
  if ('ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line) and ipv4_fields[1] not in line:
    line = line[:-4] + ' && (hdr.%s.%s == 5)) {\n'%(ipv4,ipv4_fields[1])
  if ('ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line) and ipv4_fields[0] not in line:
    line = line[:-4] + ' && (hdr.%s.%s == 4)) {\n'%(ipv4,ipv4_fields[0])
  if ('ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line) and 'checksum_error' not in line:
    line = line[:-4] + ' && (standard_metadata.checksum_error == 0)) {\n'
  if ('ip' in line and 'isValid' in line and 'hdr.' in line and 'if' in line) and ipv4_fields[3] not in line:
    patch.append(" ")
    patch.append(" ")
    #Move everything from this point forward 2 lines back
    iterator2 = len(patch) - 1
    while iterator2 > (line_number):
      patch[iterator2] = patch[iterator2-2]
      iterator2 -= 1
    #Apply the patch to check the incoming checksum
    patch[line_number+1] = '        bit<16> comperable = helper++hdr.%s.%s;\n'%(ipv4,ipv4_fields[1])
    patch[line_number+2] = line[:-4] + ' && (hdr.%s.%s >= (comperable * 4))) {\n'%(ipv4,ipv4_fields[3])
    line = '        bit<12> helper = 0;\n'

  if 'apply' in line and '{' in line and '}' in line:
    line = '    apply {\n'
    patch.append(" ")
    patch.append(" ")
    #Move everything from this point forward 3 lines back
    iterator2 = len(patch) - 1
    while iterator2 > line_number:
      patch[iterator2] = patch[iterator2-2]
      iterator2 -= 1
    #Add the checksum-verification
    patch[line_number+1] = '        verify_checksum(false,{hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s,hdr.%s.%s},hdr.%s.%s,HashAlgorithm.csum16);\n'%(ipv4,ipv4_fields[0],ipv4,ipv4_fields[1],ipv4,ipv4_fields[2],ipv4,ipv4_fields[3],ipv4,ipv4_fields[4],ipv4,ipv4_fields[5],ipv4,ipv4_fields[6],ipv4,ipv4_fields[7],ipv4,ipv4_fields[8],ipv4,ipv4_fields[10],ipv4,ipv4_fields[11],ipv4,ipv4_fields[9])
    patch[line_number+2] = '    }\n'
    additional_lines += 2
  #Write back the given line to the patch list
  patch[line_number] = line



#This functions writes out the contents of the patch to the new file
def write_patch():
  global patch
  pfile = open(PATCHED_FILE,"w")
  contents = "".join(patch)
  pfile.write(contents)
  pfile.close()

def write_time():
  global start_time
  timer = time.time()-start_time
  time_file = open(PATCHER_LOG, "w")
  time_file.write("%.5f\n"%timer)
  time_file.close()

def main():
  #First we identify the called version of the script and assign the location of the localization results to a variable
  version = int(sys.argv[3]) #Always supposed to be 2
  global localization_results
  global ipv4

  #Than we read in the header types defined in the code
  collect_header_types()
  #Assign the collected ipv4 value to our variable
  iterator = 0
  while iterator < len(header_types):
    if 'ip' in header_types[iterator] and '6' not in header_types[iterator] and 'opt' not in header_types[iterator]:
      ipv4 = header_types[iterator][:-1]
    iterator += 1

  #Collect the name of the IPv4 header fields
  ipv4_header_fields()

  #Than we copy the current source code to a new file, to modifications on this version - not to mess up the original!
  copy_original_to_patch()

  #Run the patching section
  if version == 2:
    localization_result = str(sys.argv[4])
    loc_res = open(localization_result,"r")
    for line in loc_res:
      helper = line.split(';')
      #We consider lines suspicious only, if the suspiciousness score was 1.00
      if '1.00' in helper[2]:
        line_number = int(helper[1][21:]) - 1
        patch_single_line((line_number+additional_lines))
  else:
    print "Error - We have not programmed this path yet. Should NEVER appear"
  #Write out the new patch to the file
  write_patch()
  write_time()
  print "Patcher was executed succesfully"

if __name__ == '__main__':
    main()

