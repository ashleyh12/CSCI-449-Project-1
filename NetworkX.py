'''
Networkx function should go here.

'''

import networkx as nx
import matplotlib.pyplot as plt

def create_topology_graph(filename):
    G = nx.Graph()
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        if "Traceroute to" in line:
            target_ip = line.split("Traceroute to ")[1].strip()
        elif "Destination reached" in line:
            continue  # Skip destination reached lines
        else:
            parts = line.split()
            if len(parts) >= 2:
                hop_number, hop_ip = parts[0], parts[1]
                G.add_node(hop_ip)
                if hop_number != "1.":
                    prev_hop = parts[1]
                    G.add_edge(prev_hop, hop_ip)
    
    return G

if __name__ == "__main":
    topology_graph = create_topology_graph("traceroute_results.txt")

    # Draw and display the network graph
    pos = nx.spring_layout(topology_graph)
    nx.draw(topology_graph, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, font_color="black")
    plt.show()
