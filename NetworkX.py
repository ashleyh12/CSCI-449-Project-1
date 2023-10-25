'''
Current working networkingX code.

'''
import json
import networkx as nx
import matplotlib.pyplot as plt

def create_network_topology(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    G = nx.Graph()
    target_ips_set = set()  # Use a set to filter out duplicates

    for entry in data['output']:
        target_ip = entry['target_ip']
        if target_ip not in target_ips_set:
            G.add_node(target_ip)
            target_ips_set.add(target_ip)

        for hop in entry['traceroute']:
            hop_ip = hop['ip']
            
            if not hop_ip.startswith("208"):  # Filter out IPs starting with "208"
                G.add_node(hop_ip)
                G.add_edge(target_ip, hop_ip)

    return G

def main():
    json_file = 'traceroute_results.json'  
    G = create_network_topology(json_file)

    pos = nx.spring_layout(G, k=0.1, seed=42)
    nx.draw(G, pos, with_labels=True, node_size=500, font_size=8, node_color='skyblue')
    plt.show()

if __name__ == '__main__':
    main()

