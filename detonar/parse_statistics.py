"""
Parse dataset of Cooja logs into:
files of statistics for each time window, for each node
file of neighbors for each time window, for each node
all DAOs received by the border router
"""
import ast
import csv
import math
import os

import numpy as np
import pandas as pd

import settings_parser


def _get_data(path_to_file):
    # Read csv file
    data = pd.read_csv(path_to_file, index_col=False)
    return data


def _get_unique_nodes_names(data):
    # Get names of transmitter devices
    nodes_names = data["SENDER_ID"].unique()
    # Remove nan values
    nodes_names = [i for i in nodes_names if str(i) != "nan"]
    # Remove nodes that are not sensors
    nodes_names = [i for i in nodes_names if ("SENSOR" in i or "SINKNODE" in i)]
    return nodes_names


def _parse_stats_timewindow(stats, feature_list):
    features = np.zeros(len(feature_list), dtype=float)
    neighbors = []
    # Get number of DIO received
    features[0] = stats["DIO_rcvd"].sum()
    # Get number of DIO transmitted
    features[1] = stats["APP_rcvd"].sum()
    # Get number of DAO transmitted
    features[2] = stats["DAO_txd"].sum()
    # Get number of DIS transmitted
    features[3] = stats["DIO_txd"].sum()
    # Get number of application packets received
    features[4] = stats["DIS_txd"].sum()
    # Get number of application packets transmitted
    features[5] = stats["APP_txd"].sum()
    # Current rank
    features[6] = stats["CURRENT_RANK"].iat[-1]
    # Current version
    features[7] = stats["CURRENT_VERSION"].iat[-1]
    # Time for rank change
    for i in range(1, len(stats["RANK_CHANGE_TIME"]) + 1):
        if stats["RANK_CHANGE_TIME"].iat[-i] != 0:
            features[8] = stats["RANK_CHANGE_TIME"].iat[-i]
            break
    # Time for version change
    for i in range(1, len(stats["VERSION_CHANGE_TIME"]) + 1):
        if stats["VERSION_CHANGE_TIME"].iat[-i] != 0:
            features[9] = stats["VERSION_CHANGE_TIME"].iat[-i]
            break
    # Set nr of incoming vs outgoing
    nr_incoming = stats["APP_rcvd"].sum()
    nr_outgoing = stats["APP_txd"].sum()
    if nr_incoming == nr_outgoing:
        features[10] = 1
    elif nr_outgoing != 0 and nr_incoming == 0:
        features[10] = 1
    else:
        features[10] = nr_outgoing / nr_incoming
    # List of neighbors
    for i, neighbor in enumerate(stats["NEIGHBORS"]):
        nbrs = ast.literal_eval(list(stats["NEIGHBORS"])[i])
        for count, nbr in enumerate(nbrs):
            neighbors.append(nbr)
    return features, neighbors


def _create_neighbors_file_for_node(args, neighbor_list, node):
    with open(
        f"{args.feat_folders}{args.scenario}/{args.simulation_time}/"
        f"simulation-{args.chosen_simulation}/{node}_neighbors.csv",
        "w",
        encoding="utf8",
    ) as neighbor_file:
        writer = csv.writer(neighbor_file)
        columns_neighbors = list(range(args.max_nr_neighbors))
        writer.writerow(columns_neighbors)
        for neighbors in neighbor_list:
            neighbors = list(set(neighbors))
            row = list(range(args.max_nr_neighbors))
            for i in range(len(columns_neighbors)):
                if i < len(neighbors):
                    row[i] = str(neighbors[i])
                else:
                    row[i] = 0
            writer.writerow(row)


def _create_dao_file(args):
    with open(
        f"{args.feat_folders}{args.scenario}/{args.simulation_time}/"
        f"simulation-{args.chosen_simulation}/all_DAOs.csv",
        "w",
        encoding="utf8",
    ) as daos_file:
        all_daos = _get_data(
            os.path.join(
                os.getcwd(),
                "..",
                args.data_dir,
                args.scenario,
                f"Packet_Trace_{args.simulation_time}s",
                args.chosen_simulation + "_dao.csv",
            )
        )
        all_daos.to_csv(daos_file, index=False)
    return all_daos


def _get_time_window_data(data, index, args, full_data=False):
    time_window = args.time_window
    if full_data:
        start_time = args.time_start * 1e6
    else:
        start_time = index * time_window * 1e6
    end_time = ((index + 1) * time_window) * 1e6
    # Get all packets that have been received between start and end time (depending on window size)
    condition = (data[args.time_feat_micro] > start_time) & (
        data[args.time_feat_micro] <= end_time
    )
    sequence = data[condition]
    return sequence


def _create_changed_parent_column(args, all_daos, node):
    changed_parent = np.zeros(int(args.simulation_time / args.time_window), dtype=int)
    last_parent_id = ""
    node_daos = all_daos[all_daos["SOURCE_ID"] == node]
    for row in node_daos.iterrows():
        parent = row[-1]["PARENT_ID"]
        if not parent == last_parent_id:
            time = row[-1]["TIME"]
            time_step = int((time / 1e6) / args.time_window)
            changed_parent[time_step] = 1
        last_parent_id = row[-1]["PARENT_ID"]
    return changed_parent


def _parse_stats(args):
    # Use attack classification features except "changed parent" which is added later
    feature_list = args.attack_classification_features[
        : len(args.attack_classification_features) - 1
    ]

    data = _get_data(
        os.path.join(
            os.getcwd(),
            "..",
            args.data_dir,
            args.scenario,
            f"Packet_Trace_{args.simulation_time}s",
            args.chosen_simulation + "_stats.csv",
        )
    )

    nodes_names = _get_unique_nodes_names(data)

    for node in nodes_names:
        if not os.path.exists(
            f"{args.feat_folders}{args.scenario}/{args.simulation_time}/"
            f"simulation-{args.chosen_simulation}"
        ):
            os.makedirs(
                f"{args.feat_folders}{args.scenario}/{args.simulation_time}"
                f"/simulation-{args.chosen_simulation}"
            )
        neighbor_list = []
        # Create stats-file for node
        with open(
            f"{args.feat_folders}{args.scenario}/{args.simulation_time}"
            f"/simulation-{args.chosen_simulation}/{node}_stats.csv",
            "w",
            encoding="utf8",
        ) as output_file:
            # Write column names to output file
            writer = csv.writer(output_file)
            writer.writerow(feature_list)
            # Get all packets transmitted by node
            id_condition = data["SENDER_ID"] == node
            stats_packets = data[id_condition]
            # Get index for windowing the network traffic
            start_index = 0
            end_index = math.floor(args.simulation_time) / args.time_window
            # For each index get the corresponding network traffic window and extract the features
            for index in range(int(start_index), int(end_index)):
                # Get transmitted, received and all packets within the time window
                stats = _get_time_window_data(
                    stats_packets, index, args, full_data=False
                )
                if not stats.empty:
                    features, neighbors = _parse_stats_timewindow(stats, feature_list)
                neighbor_list.append(neighbors)
                # Append the features row in feature file
                writer.writerow(features)
        # Create neighbors-file for node
        _create_neighbors_file_for_node(args, neighbor_list, node)

        # Create a file containing all DAOs sent
        all_daos = _create_dao_file(args)

        # Create column of whether node changed parent for timestep or not
        changed_parent = _create_changed_parent_column(args, all_daos, node)
        # Insert changed parent-column into stats-file
        stats_csv = pd.read_csv(
            f"{args.feat_folders}{args.scenario}/{args.simulation_time}/"
            f"simulation-{args.chosen_simulation}/{node}_stats.csv",
            index_col=False,
        )
        stats_csv.insert(11, "changed_parent", changed_parent)
        stats_csv.to_csv(
            f"{args.feat_folders}{args.scenario}/{args.simulation_time}/"
            f"simulation-{args.chosen_simulation}/{node}_stats.csv"
        )


def main():
    args = settings_parser.arg_parse()
    _parse_stats(args)


if __name__ == "__main__":
    main()
