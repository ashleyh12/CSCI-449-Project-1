from scapy.all import *
import networkx as nx
import matplotlib.pyplot as plt
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def custom_traceroute(target_ip, G):
    max_hops = 8  # Maximum number of hops

    print(f"Traceroute to {target_ip}")

    prev_hop = None  # To track the previous hop

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP()

        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0, timeout=2, iface="en0")

        if reply is None:
            print(f"{ttl}. *")
            current_hop = None
        elif reply.type == 0:
            print(f"{ttl}. {reply.src}")
            current_hop = reply.src
            if reply.src == target_ip:
                print("Destination reached.")
                break
        else:
            print(f"{ttl}. {reply.src} (Type {reply.type})")
            current_hop = reply.src

        if prev_hop and current_hop:
            G.add_node(prev_hop)
            G.add_node(current_hop)
            G.add_edge(prev_hop, current_hop)

        prev_hop = current_hop

    return G

if __name__ == "__main__":
    target_ips = ["10.0.0.0", "138.238.0.0"]  # Replace with your list of IP addresses

    G = nx.Graph()

    for target_ip in target_ips:
        G = custom_traceroute(target_ip, G)
        print("\n")

        # Print the IP address and number of every hop
        hop_number = 1
        for hop in G.nodes():
            print(f"Hop {hop_number}: {hop}")
            hop_number += 1

        if target_ip in G.nodes():
            print("Done!")

    # Draw and display the network graph
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, font_color="black")
    plt.show()

    '''Things to do next: separate the traceroute function and the network graph function

    Traceroute function should trace through then dump the ip addresses into a file ~ This file

    Network graph function should read the file and create the network graph ~ We'll need to create another file to do this.

    Step 1: Remove the networkx code from this file and put it into a new file called network_graph.py
    Step 2: Make the traceroute code dump the ip addresses into a file (There will definetly be more sub steps)
    Step 3: Have the network graph code read the file and create the network graph

    '''