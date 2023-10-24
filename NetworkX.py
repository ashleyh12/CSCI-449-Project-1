'''
Networkx function should go here.

'''
import json
import networkx as nx

# Create an empty directed graph
G = nx.DiGraph()

# Open the file for reading
with open("traceroute_results.json", "r") as f:
    json_data = ""
    for line in f:
        json_data += line.strip()

        # Check if the line contains a complete JSON object
        if json_data and json_data[-1] == "}":
            try:
                data = json.loads(json_data)

                if "target_ip" in data and "traceroute" in data:
                    target_ip = data["target_ip"]
                    traceroute = data["traceroute"]

                    # Add nodes and edges to the graph based on the traceroute data
                    previous_hop = None
                    for hop in traceroute:
                        ip = hop.get("ip")
                        if ip:
                            G.add_node(ip)
                            if previous_hop:
                                G.add_edge(previous_hop, ip)
                            previous_hop = ip

                json_data = ""

            except json.JSONDecodeError:
                json_data = ""



