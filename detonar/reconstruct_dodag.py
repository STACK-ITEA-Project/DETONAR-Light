# Python modules
import os
import time as tm

import networkx as nx

# Python files
import settings_parser


def extract_data_up_to(data, time, args):
    # From the pandas dataframe extract only those packets arrived up to a certain second
    condition = data[args.time_feat_sec] <= time
    data = data[condition]
    return data


def refine_edges_list(edges):
    edges_to_remove = []
    # For each edges in the list of edges check if two edges have the same source
    for i in range(len(edges)):
        for j in range(i + 1, len(edges)):
            source_node_first_link = edges[i][0]
            source_node_second_link = edges[j][0]
            # Remove any link but the oldest
            if source_node_first_link == source_node_second_link:
                edges_to_remove.append(edges[i])
    # Get a set from the list of edges to remove and remove all of them from the original edges list
    edges_to_remove = set(edges_to_remove)
    for edge in edges_to_remove:
        edges.remove(edge)

    return edges


def get_dodag(data):
    # Get DAOs where source_ID == transmitter ID (the first step in the route towards the root)
    # Receiver of these packets^ is the parent
    source_ids = data["SOURCE_ID"].unique()
    edges = []
    # For each node sending a DAO, find the latest DAO and add it as an edge
    for node in source_ids:
        all_daos = data[data["SOURCE_ID"] == node]
        latest_condition = all_daos["TIME"] == max(all_daos["TIME"])
        latest_dao = all_daos[latest_condition]
        parent = latest_dao["PARENT_ID"]
        parent_array = parent.values
        edges.append((node, parent_array[0]))
    # Use nx to obtain the graph corresponding to the dodag
    dodag = nx.Graph()
    # Build the DODAG graph from nodes and edges lists
    dodag.add_nodes_from(source_ids)
    dodag.add_edges_from(edges)
    return dodag


def extract_dodag_before_after(data, list_nodes, neighbors, time, args):
    tic = tm.perf_counter()
    # Get DODAG some time steps before the anomaly is raised
    window_time = args.time_window
    data_before = extract_data_up_to(data, (time - 1 * window_time) * 1e6, args)
    dodag_before = get_dodag(data_before)
    # Plot the graph corresponding to the DODAG extracted
    # fig, axs = plt.subplots(1, 3, figsize=(30,15))
    # axs[0].set_title('DODAG before anomaly')
    # nx.draw(dodag_before, with_labels=True, ax=axs[0])
    # Get DODAG after the anomaly is raised
    data_after = extract_data_up_to(data, time * 1e6, args)
    dodag_after = get_dodag(data_after)
    # Plot the graph corresponding to the DODAG extracted
    # pos = nx.spring_layout(dodag_after)
    # axs[1].set_title('DODAG after anomaly')
    # nx.draw(dodag_after, pos=pos, with_labels=True, ax=axs[1])
    # nx.draw(dodag_after.subgraph(list_nodes), pos=pos, node_color='orange', with_labels=True, ax=axs[1])
    # nx.draw(dodag_after.subgraph(neighbors), pos=pos, node_color='yellow', with_labels=True, ax=axs[1])
    # Compute difference between graphs and plot everything
    dodag_difference = nx.difference(dodag_after, dodag_before)
    dodag_difference.remove_nodes_from(list(nx.isolates(dodag_difference)))
    # axs[2].set_title('DODAG difference')
    # nx.draw(dodag_difference, with_labels=True, ax=axs[2])
    # plt.suptitle(args.scenario)
    toc = tm.perf_counter()
    # print('Everything DODAG took {:.5f}'.format(toc - tic))
    # plt.show()
    if len(dodag_difference) == 0:
        return False, []
    nodes_changing = dodag_difference.nodes()

    return True, nodes_changing


def main():
    # Just a trial to check if the code works, the main shouldn't be used actually
    args = settings_parser.arg_parse()
    window_time = 10
    time_step = 25
    time_anomaly = time_step * 10 + 10
    extract_dodag_before_after(
        os.path.join(
            os.getcwd(), "..", args.data_dir, "Sinkhole", "Packet_Trace_600s/001.csv"
        ),
        time_anomaly,
        window_time,
    )


if __name__ == "__main__":
    main()
