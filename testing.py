'''
This code is testing the traceroute function with multithreading (CAUTION): STILL NEEDS NETWORK FUNCTION REMOVED
'''

'''from scapy.all import *
import networkx as nx
import matplotlib.pyplot as plt
import threading

# Function to perform a custom traceroute

def custom_traceroute(target_ip, G, hop_number):
    max_hops = 8  # Maximum number of hops

    print(f"Traceroute to {target_ip}")

    prev_hop = None  # To track the previous hop

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP()

        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0, timeout=2, iface="en0")

        if reply is None:
            print(f"Hop {hop_number}. *")
            current_hop = None
        elif reply.type == 0:
            print(f"Hop {hop_number}. {reply.src}")
            current_hop = reply.src
            if reply.src == target_ip:
                print("Destination reached.")
                break
        else:
            print(f"Hop {hop_number}. {reply.src} (Type {reply.type})")
            current_hop = reply.src

        if prev_hop and current_hop:
            G.add_node(prev_hop)
            G.add_node(current_hop)
            G.add_edge(prev_hop, current_hop)

        prev_hop = current_hop

    return G

# Function to execute the traceroutes
def run_traceroutes():
    # Define the IP address ranges for public and private IPs
    public_ip_range = ["138.238.0.0", "138.238.255.255"]
    private_ip_range = ["10.0.0.0", "10.255.255.255"]

    G = nx.Graph()

    # Create a list of target IP addresses within the specified range
    target_ips = []

    # Generate target IPs for public IP address space
    for i in range(0, 256, 8):
        for j in range(256):
            target_ips.append(f"138.238.{i}.{j}")

    # Generate target IPs for private IP address space
    for i in range(256):
        for j in range(256):
            target_ips.append(f"10.{i}.{j}.1")

    # Create a thread for each target IP
    threads = []
    hop_number = 1

    for target_ip in target_ips:
        thread = threading.Thread(target=custom_traceroute, args=(target_ip, G, hop_number))
        threads.append(thread)
        thread.start()
        hop_number += 1

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Print the IP address and number of every hop in the combined graph
    for hop in G.nodes():
        print(hop)

    # Draw and display the network graph
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, font_color="black")
    plt.show()

# Call the function to run traceroutes
run_traceroutes()'''


#More test code to try out 
'''from scapy.all import *
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def custom_traceroute(target_ip, output_file):
    max_hops = 7  # Maximum number of hops

    print(f"Traceroute to {target_ip}")

    with open(output_file, "a") as f:  # Open the file in "a" mode for append
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434)
            reply = sr1(pkt, verbose=0, timeout=5)

            if reply is None:
                #f.write(f"{ttl}. *\n")
                break
            elif reply.type == 0:
                f.write(f"{ttl}. {reply.src}\n")
                if reply.src == target_ip:
                    f.write("Destination reached.\n")
                    break

if __name__ == "__main__":
    # Define ranges of public and private IPs
    public_ip_range = range(1, 10)  # Change this to the desired range
    private_ip_range = range(1, 10)  # Change this to the desired range

    # Open the output file in append mode (will create or append to the same file)
    with open("traceroute_results.txt", "a+") as f:
        f.write("Traceroute Results\n\n")

    for i in public_ip_range:
        target_ip = f"138.238.0.{i}"
        custom_traceroute(target_ip, "traceroute_results.txt")
        print(f"Traceroute to {target_ip} completed and results appended to traceroute_results.txt")

    for i in private_ip_range:
        target_ip = f"10.0.0.{i}"
        custom_traceroute(target_ip, "traceroute_results.txt")
        print(f"Traceroute to {target_ip} completed and results appended to traceroute_results.txt")
'''