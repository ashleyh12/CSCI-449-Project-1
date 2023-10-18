'''
Networkx function should go here.

'''

# Draw and display the network graph
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, font_color="black")
plt.show()
