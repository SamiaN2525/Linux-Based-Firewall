'''
The below code was originally written by Hoda & Samia.
This updated code allows the user to dynamically choose which iptables rules
to enable or disable at runtime, while still maintaining a stateful firewall 
through NFQUEUE and Scapy in Python, and logging firewall events.

Hoda used the following links for inspiration and syntax details:
- https://docs.trellix.com/bundle/endpoint-security-10.6.0-firewall-product-guide-windows/page/GUID-9023959B-AA8A-43D4-83ED-FF6388BC3A5A.html --> State table details for the firewall
- https://github.com/Roshan-Poudel/Python-Scapy-Packet-Sniffer/blob/master/python-packet-sniffer.py --> How to work with Scapy
- https://pypi.org/project/NetfilterQueue/ --> How to work with NFQUEUE
Samia used the following links as sources:
-https://radagast.ca/how_to_build_a_firewall/how_to_build_a_firewall.html
-https://organicprogrammer.com/2022/05/04/how-to-write-a-netfilter-firewall-part1/
-https://www.linuxjournal.com/article/9521 -->Main Components of linux based firewall
'''
import os #For setting up iptables rules
import time #for time stamping on the log file
import logging #for logging events ina  file
import socket #to determine local ip addresses
import ipaddress #to validate ip addresses
import threading #to run NFQUEUE listner in a thread
from netfilterqueue import NetfilterQueue # to handle NFQUEUE packets
from scapy.all import IP, TCP, UDP, ICMP # for packet manipulation or parsing

#Allow logging on a file named firewall.log to keep track of all connection
#in the purpose of being stateful
#level will log all events at INFO level and above
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')

#Initialize state table (dicitionary) to store connections in it
state_table = {}

#We set all flags tp False at first so we apply the rules later correctly
block_icmp_flag = False
block_http_flag = False
block_ssh_flag = False  
allow_established = False
blocked_ips = set()  


#Get the local IP address (used to determine direction of traffic)
local_ip = socket.gethostbyname(socket.gethostname())

#Enable IP forwarding ro allow the vm to act as a router by forwarding
#packets from one interface to another
def ip_forwarding():
    try:
        #Enable IP forwarding
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")#writes the value to 1 int he corresponding file
        logging.info("IP forwarding is on.")#log the message
    except Exception as e:
        logging.error(f"Failed to enable IP forwarding: {e}")

#Set up iptables rules to send packets to NFQUEUE, to allow 
# for packets inspection and editing by the user 
def setup_iptables():
    try:
        #Flush first to avoid duplicates
        #clear any existing rule  to prevent conflicts
        #(could be) be removed to keep the firewall state but we kept it for the sake of testing
        os.system("sudo iptables -F")
        #Direct all incoming and outcoming to NFQUEUE so Python can handle them with queue number of 0
        os.system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0")
        os.system("sudo iptables -A FORWARD -j NFQUEUE --queue-num 0")
        #log the corrresponding message
        logging.info("iptables rules set successfully (NFQUEUE).")
    except Exception as e:
        logging.error(f"Failed to set iptables rules: {e}")

#Clear all iptables rules restoring the system defualt behavior
def clear_iptables():
    try:
        #flush flag used
        os.system("sudo iptables -F") 
        #log correslonding message 
        logging.info("iptables rules cleared successfully.")
    except Exception as e:
        logging.error(f"Failed to clear iptables rules: {e}")

#Validate if the input string is a valid IP address
#ensures that only valid IP addresses are processed 
# such as int he case blocking or re-allowing traffic
def validate_ip(ip):
    try:
        #converts the input into an IP address object if validated
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

##All flags used below are for the purpose of tracking wiether the rule is True or Flase

#turn on a global rule that allows established connection
#general rule that serves the purpose of being stateful
#variable is declared as global to track the state of established 
# connection rules across the program
def establishing_rule_on():
    global allow_established
    allow_established = True
    print("Established connections rule is ON")
#turn off the above rule
def establishing_rule_off():
    global allow_established
    allow_established = False
    print("Established connections rule is OFF")
#allows ICMP traffic (ping requests,...).
def allow_icmp():
    global block_icmp_flag
    block_icmp_flag = False
    print("ICMP traffic is allowed")
#turn off the above rule or if already activated blocks this traffic
def block_icmp():
    global block_icmp_flag
    block_icmp_flag = True
    print("ICMP traffic is blocked")
#allows HTTP and HTTPS traffic 
def allow_http():
    global block_http_flag
    block_http_flag = False
    print("HTTP and HTTPS traffic are allowed")
#turn off the above rule or if already activated blocks this traffic
def block_http():
    global block_http_flag
    block_http_flag = True
    print("HTTP and HTTPS traffic are blocked")
#blocks traffic from a specific IP address
def block_traffic():
    ip = input("Enter the IP address to block: ")
    #use validate_ip(ip) to ensure 
    #the provided input is a valid IP address
    #blocked_ips (assumed to be declared globally) 
    #stores the list of blocked IPs for quick lookup
    if validate_ip(ip):
        #adds it to the blocked_ips set
        blocked_ips.add(ip)
        print(f"Traffic from {ip} is now blocked.")
    else:
        print("Invalid IP address")
# deactivate the above rule
def reallow_traffic():
    ip = input("Enter the IP address to re-allow: ")
    if validate_ip(ip):
        if ip in blocked_ips:
            blocked_ips.remove(ip) #through the rmove function from the list
            print(f"Traffic from {ip} is now re-allowed.")
        else:
            print("IP was not blocked previously.")
    else:
        print("Invalid IP address")
#allow ssh traffic on port 22
def allow_ssh():
    global block_ssh_flag
    block_ssh_flag = False
    print("SSH (port 22) traffic is allowed")
#bloack ssh traffic on port 22
def block_ssh():
    global block_ssh_flag
    block_ssh_flag = True
    print("SSH (port 22) traffic is blocked")

#processe a network packet and extracts relevant 
#details like protocol, source/destination IPs, ports
#and categorizes it as incoming or outgoing 
#returns a unique connection ID (conn_id) and metadata about the packet
def packet_processing(packet):
    #converts the raw packet payload into a scapy ip layer packet
#packet.get_payload() retrieves the raw packet payload from the input
#IP() parses the raw packet into an IP-layer object for easier field access
    scapy_packet = IP(packet.get_payload()) 
    #used to store the protocol type later
    protocol = None #initializes the protocol variable as none
    source_ip = scapy_packet.src
    destination_ip = scapy_packet.dst
    source_port = None #initialized as none
    destination_port = None #initialized as none
#determines if the packet contains a TCP layer
#checks if the packet includes the TCP protocol layer
#If True the protocol is identified as TCP, and ports are extracted
    if scapy_packet.haslayer(TCP):
        protocol = 'tcp'
        source_port = scapy_packet[TCP].sport
        destination_port = scapy_packet[TCP].dport
#determines if the packet contains a UDP layer
#checks if the packet includes the UDP protocol layer
#If True the protocol is identified as UDP , and ports are extracted  
    elif scapy_packet.haslayer(UDP):
        protocol = 'udp'
        source_port = scapy_packet[UDP].sport
        destination_port = scapy_packet[UDP].dport
#classify the packet as incoming or outgoing
#compares the packet’s destination IP with the local system’s IP 
#if the destination IP matches the local IP the packet is marked as incoming
#it not it is marked as outgoing
    direction = "incoming" if destination_ip == local_ip else "outgoing"
    if protocol:
        #generates a unique connection identifier for TCP/UDP packets
        #combines the protocol source/destination IPs and ports into a tuple (conn_id) which
        # identifies the connection

        conn_id = (protocol, source_ip, destination_ip, source_port, destination_port)
        #return Metadata for TCP/UDP packets
        return conn_id, {
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "timestamp": time.time(),
            "timeout": 1800,  # 30 minutes timeout to keep track of the connection and let it be stateful
            "direction": direction
        }
    #returns both the conn_id and a metadata dictionary
    else:
        # Could be icmp or anything else
        return None, {
            "protocol": "icmp" if scapy_packet.haslayer(ICMP) else "other",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": None,
            "destination_port": None,
            "timestamp": time.time(),
            "timeout": 1800,
            "direction": direction
        }
#cleans up stale connections from the state_table 
#to prevent memory or performance issues
#iterates over all connections in the state_table.
#converts state_table.items() to a list to safely modify
#the dictionary while iterating
#if current_time - state["timestamp"] > state["timeout"]
#checks if a connection has exceeded its timeout (stale connection)
#where the timeout is predefined (30 minutes in the packet_processing function).\
def delete_connections():
    current_time = time.time()
    for conn_id, state in list(state_table.items()):
        if current_time - state["timestamp"] > state["timeout"]:
            logging.info(f"Deleting stale connection: {conn_id}")
            del state_table[conn_id]
            #deletes the stale connection from the state_table.
#Determines whether a packet should be blocked based on various rules 
#checks if the source or destination IP of the packet exists in the global blocked_ips list
#If True: Returns (True, "IP_BLOCKED").
def should_block_packet(conn_state):
    # Check if IP is blocked
    if conn_state["source_ip"] in blocked_ips or conn_state["destination_ip"] in blocked_ips:
        return True, "IP_BLOCKED"

    # Check ICMP blocking
    if conn_state["protocol"] == "icmp" and block_icmp_flag:
        return True, "ICMP_BLOCKED"

    # Check HTTP blocking
    if conn_state["protocol"] == "tcp" and block_http_flag:
        if conn_state["destination_port"] in [80, 443]:
            return True, "HTTP_BLOCKED"
        
    # Check SSH blocking
    if conn_state["protocol"] == "tcp" and conn_state["destination_port"] == 22 and block_ssh_flag:
        return True, "SSH_BLOCKED"

    return False, ""
    
    # Check established if needed. If allow_established is True,
    # we only allow packets that are ESTABLISHED or RELATED.
    # In our simplified logic, we have a state_table that tracks connections.
    # We'll consider a connection "new" if it's not in state_table.
    # If allow_established is on, only packets that are part of existing connections are allowed.
    # We'll handle this logic in the main packet handler.

    return False, ""
#processes packets from NFQUEUE, applies rules and either blocks 
#or accepts packets based on conditions.
def NFQUEUE_process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    conn_id, conn_state = packet_processing(packet)
    delete_connections()

    # If we have a recognizable connection (TCP/UDP)
    # or an ICMP/other packet with details
    # Check blocking conditions first
    block, reason = should_block_packet(conn_state)

    # If allow_established is True and this is a new connection (not in state_table),
    # and not HTTP/HTTPS or allowed traffic, we can block it as well
    if allow_established and conn_state["protocol"] in ["tcp", "udp"]:
        if conn_id not in state_table and (conn_state["destination_port"] not in [80,443]):
            block = True
            reason = "NON_ESTABLISHED_CONNECTION"

    # If block is True, log and drop
    if block:
        logging.info(f"Blocked packet: SRC={conn_state['source_ip']} "
                     f"DST={conn_state['destination_ip']} "
                     f"SPT={conn_state['source_port']} DPT={conn_state['destination_port']} "
                     f"PROTO={conn_state['protocol']} REASON={reason}")
        packet.drop()
        return

    # If not blocked:
    # For ICMP:
    if conn_state["protocol"] == "icmp":
        logging.info(f"Accepted ICMP packet: SRC={conn_state['source_ip']} DST={conn_state['destination_ip']}")
        packet.accept()
        return

    # For TCP/UDP:
    if conn_id and conn_state["protocol"] in ["tcp", "udp"]:
        if conn_id in state_table:
            state_table[conn_id]["timestamp"] = time.time()
            logging.info(f"Accepted existing connection: SRC={conn_state['source_ip']} "
                         f"DST={conn_state['destination_ip']} SPT={conn_state['source_port']} "
                         f"DPT={conn_state['destination_port']} PROTO={conn_state['protocol']}")
            packet.accept()
        else:
            # New connection
            state_table[conn_id] = conn_state
            logging.info(f"Accepted new connection: SRC={conn_state['source_ip']} "
                         f"DST={conn_state['destination_ip']} SPT={conn_state['source_port']} "
                         f"DPT={conn_state['destination_port']} PROTO={conn_state['protocol']}")
            packet.accept()
    else:
        # Non TCP/UDP and not ICMP: just accept
        logging.info(f"Accepted non-TCP/UDP packet: SRC={conn_state['source_ip']} DST={conn_state['destination_ip']} PROTO={conn_state['protocol']}")
        packet.accept()

def start_nfqueue_listener():
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, NFQUEUE_process_packet)

    try:
        logging.info("Starting NFQUEUE listener")
        nfqueue.run()
    except KeyboardInterrupt:
        logging.info("Stopping NFQUEUE listener")
    finally:
        nfqueue.unbind()

def print_menu():
    print("""CHOOSE FROM THE BELOW OPTIONS:
1. Activate established-related rule
2. Deactivate established rule
3. Allow ICMP traffic
4. Block ICMP traffic
5. Allow HTTP traffic
6. Block HTTP traffic
7. Block SSH traffic
8. Allow SSH traffic
9. Block traffic from a certain IP address
10. Re-allow traffic from an IP address you already blocked
11. Clear all iptables rules
12. Exit the program

""")

def main():
    print("WELCOME TO THE FIREWALL")
    ip_forwarding()
    setup_iptables()

    # Start NFQUEUE listener in a separate thread so we can still interact with the user.
    nfqueue_thread = threading.Thread(target=start_nfqueue_listener, daemon=True)
    nfqueue_thread.start()

    while True:
        print_menu()
        choice = input("Enter your choice please: ")

        if choice == "1":
            establishing_rule_on()
        elif choice == "2":
            establishing_rule_off()
        elif choice == "3":
            allow_icmp()
        elif choice == "4":
            block_icmp()
        elif choice == "5":
            allow_http()
        elif choice == "6":
            block_http()
        elif choice == "7":
            block_ssh()
        elif choice == "8":
            allow_ssh()
        elif choice == "9":
            block_traffic()
        elif choice == "10":
            reallow_traffic()
        elif choice == "11":
            clear_iptables()
        elif choice == "12":
            print("Exiting the program...")
            clear_iptables()
            break
        

        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
#as noticed many functions are created can be manipulated and added very easily
# bu just adding th choice to the elif statements and calling the function in the main def
# to be also an option
#for the user to use them in the simplified interface
#the functions were not exposed as user options because 
# they handle backend processes, automate real-time tasks
# or are low-level operations that would overcomplicate the interface. 
# instead the tool focuses on providing high-level configuration options 
# that balance usability and functionality leaving complex operations to be handled seamlessly in the background