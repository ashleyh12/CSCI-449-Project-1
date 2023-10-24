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

    for entry in data['output']:
        target_ip = entry['target_ip']
        G.add_node(target_ip)

        for hop in entry['traceroute']:
            hop_ip = hop['ip']
            G.add_node(hop_ip)
            G.add_edge(target_ip, hop_ip)

    return G

def main():
    json_file = 'traceroute_results.json'  
    G = create_network_topology(json_file)

    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, node_size=900, font_size=8, node_color='skyblue')
    plt.show()

if __name__ == '__main__':
    main()
 
 