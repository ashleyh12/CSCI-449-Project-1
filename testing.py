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
'''
import threading
from scapy.all import *
import logging
import json

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def custom_traceroute(target_ip, output_file):
    max_hops = 8  # Maximum number of hops
    traceroute_data = {
        "target_ip": target_ip,
        "traceroute": []
    }

    print(f"Traceroute to {target_ip}")

    prev_hop = None  # To track the previous hop

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0, timeout=5, iface="en0")

        if reply is not None:
            hop_data = {
                "hop": ttl,
                "ip": reply.src,
            }

            if reply.type == 0:
                print(f"{ttl}. {reply.src}")
                current_hop = reply.src
                if reply.src == target_ip:
                    print("Destination reached.")
                    break
            else:
                print(f"{ttl}. {reply.src} (Type {reply.type})")
                current_hop = reply.src

            traceroute_data["traceroute"].append(hop_data)

        prev_hop = current_hop

    # Save the traceroute data to a JSON file
    with open(output_file, 'a') as f:
        json.dump(traceroute_data, f, indent=4)

if __name__ == "__main__":
    public_ip_range = range(1, 100)  # Change this to the desired range
    private_ip_range = range(1, 100)  # Change this to the desired range

    output_file = "traceroute_results.json"

    with open(output_file, 'a') as f:
        f.write("Traceroute Results\n\n")

    threads = []

    for i in public_ip_range:
        target_ip = f"138.238.0.{i}"
        t = threading.Thread(target=custom_traceroute, args=(target_ip, output_file))
        threads.append(t)
        t.start()

    for i in private_ip_range:
        target_ip = f"10.0.0.{i}"
        t = threading.Thread(target=custom_traceroute, args=(target_ip, output_file))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
'''

from scapy.all import *
import logging
import json
from multiprocessing import Pool
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Set the maximum number of IP addresses to process
MAX_IP_ADDRESSES = 1000000

def save_last_ip(target_ip):
    # Save the last processed IP address to a file
    with open("last_processed_ip.txt", "w") as f:
        f.write(target_ip)

def load_last_ip():
    # Load the last processed IP address from the file
    try:
        with open("last_processed_ip.txt", "r") as f:
            return f.read()
    except FileNotFoundError:
        return None

def custom_traceroute(target_ip, output_file):
    max_hops = 8  # Maximum number of hops
    traceroute_data = {
        "target_ip": target_ip,
        "traceroute": []
    }

    print(f"Traceroute to {target_ip}")

    prev_hop = None  # To track the previous hop

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0, timeout=5, iface="en0")

        if reply is not None:
            hop_data = {
                "hop": ttl,
                "ip": reply.src,
            }

            if reply.type == 0:
                print(f"{ttl}. {reply.src}")
                current_hop = reply.src
                if reply.src == target_ip:
                    print("Destination reached.")
                    break
            else:
                print(f"{ttl}. {reply.src} (Type {reply.type})")
                current_hop = reply.src

            traceroute_data["traceroute"].append(hop_data)

        prev_hop = current_hop

    # Save the last processed IP address
    save_last_ip(target_ip)

    # Save the traceroute data to a JSON file
    with open(output_file, 'a') as f:
        json.dump(traceroute_data, f, indent=4)

def generate_ip_range(start, end, max_addresses):
    last_processed_ip = load_last_ip()

    for a in range(start[0], end[0] + 1):
        for b in range(start[1], end[1] + 1):
            for c in range(start[2], end[2] + 1):
                for d in range(start[3], end[3] + 1):
                    target_ip = f"{a}.{b}.{c}.{d}"

                    if last_processed_ip and target_ip == last_processed_ip:
                        return  # Stop generating IP addresses when the limit is reached
                    yield target_ip

if __name__ == "__main__":
    public_ip_start = (138, 238, 0, 0)
    public_ip_end = (138, 238, 255, 255)
    private_ip_start = (10, 0, 0, 0)
    private_ip_end = (10, 255, 255, 255)

    output_file = "traceroute_results.json"

    ip_addresses = []
    for target_ip in generate_ip_range(public_ip_start, public_ip_end, MAX_IP_ADDRESSES):
        ip_addresses.append(target_ip)

    for target_ip in generate_ip_range(private_ip_start, private_ip_end, MAX_IP_ADDRESSES):
        ip_addresses.append(target_ip)

    # Use multiprocessing to run the traceroutes
    with Pool(processes=10) as pool:
        pool.starmap(custom_traceroute, [(ip, output_file) for ip in ip_addresses])
