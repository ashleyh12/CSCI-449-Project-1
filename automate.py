from scapy.all import *
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def custom_traceroute(target_ip, G, output_file):
    max_hops = 7  # Maximum number of hops

    print(f"Traceroute to {target_ip}")

    prev_hop = None  # To track the previous hop

    with open(output_file, 'a') as f:
        f.write(f"Traceroute to {target_ip}\n")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0, timeout=5, iface="en0")

        if reply is None:
            print(f"{ttl}. *")
            current_hop = None
        elif reply.type == 0:
            print(f"{ttl}. {reply.src}")
            current_hop = reply.src
            if reply.src == target_ip:
                print("Destination reached.")
                with open(output_file, 'a') as f:
                    f.write(f"{ttl}. {reply.src} (Destination reached)\n")
                break
        else:
            print(f"{ttl}. {reply.src} (Type {reply.type})")
            current_hop = reply.src

        with open(output_file, 'a') as f:
            f.write(f"{ttl}. {reply.src}\n")

        if prev_hop and current_hop:
            G.add_node(prev_hop)
            G.add_node(current_hop)
            G.add_edge(prev_hop, current_hop)

        prev_hop = current_hop

    return G

if __name__ == "__main__":
    public_ip_range = range(1, 10)  # Change this to the desired range
    private_ip_range = range(1, 10)  # Change this to the desired range

    G = nx.Graph()
    output_file = "traceroute_results.txt"

    with open(output_file, 'a') as f:
        f.write("Traceroute Results\n\n")

    for i in public_ip_range:
        target_ip = f"138.238.0.{i}"
        G = custom_traceroute(target_ip, G, output_file)
        print("\n")

    for i in private_ip_range:
        target_ip = f"10.0.0.{i}"
        G = custom_traceroute(target_ip, G, output_file)
        print("\n")


    '''Things to do next: separate the traceroute function and the network graph function

    Traceroute function should trace through then dump the ip addresses into a file ~ This file

    Network graph function should read the file and create the network graph ~ We'll need to create another file to do this.

    Step 1: Remove the networkx code from this file and put it into a new file called NetworkX.py
    Step 2: Make the traceroute code dump the ip addresses into a file (There will definitely be more sub steps)
    Step 3: Have the network graph code read the file and create the network graph

    '''
