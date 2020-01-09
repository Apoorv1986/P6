#Function to translate the previously read headers
#into headers types defined for scapy
def return_scapy_definitions(x): #TODO: add the remaining basic scapy definitions
    return {
       x           : x + '()/',
      'ethernet\n' : 'Ether()/',
      'vlan_tag\n' : 'Dot1Q()/',
      'ipv4\n'     : 'IP()/',
      'ethernet' : 'Ether()/',
      'vlan_tag' : 'Dot1Q()/',
      'ipv4'     : 'IP()/',
      'udp'      :  'UDP()/',
    }[x]

def return_scapy_protocol_types(x): #TODO: add the remaining basic scapy definitions
    return {
       x          :  x,
      'etherType' : 'type',
    }[x]


