# Python modules
import pandas as pd
import numpy as np
import math
import os
import glob
import random
from random import randint
import time as tm
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARIMA
import pmdarima as pm
from sklearn.metrics import mean_squared_error
import matplotlib.pyplot as plt
import warnings

warnings.filterwarnings("ignore")
import _pickle as pickle
# Python files
import settings_parser


def approximate_entropy(U, m, r):
    U = np.array(U)
    N = U.shape[0]

    def _phi(m):
        z = N - m + 1.0
        x = np.array([U[i:i + m] for i in range(int(z))])
        X = np.repeat(x[:, np.newaxis], 1, axis=2)
        C = np.sum(np.absolute(x - X).max(axis=2) <= r, axis=0) / z
        return np.log(C).sum() / z

    return abs(_phi(m + 1) - _phi(m))


# Variational coefficient is defined as the ratio between variance and mean
def variational_coefficient(series):
    if (np.mean(np.asarray(series)) == 0):
        return np.std(np.asarray(series))
    return np.std(np.asarray(series)) / np.mean(np.asarray(series))


def check_feature_with_arima(train, real_value, args):
    conf_int = [[0, 0]]
    try:
        model = pm.auto_arima(train, start_p=1, start_q=1,
                              test='adf',  # use adftest to find optimal 'd'
                              max_p=3, max_q=3,  # maximum p and q
                              m=1,  # frequency of series
                              d=None,  # let model determine 'd'
                              seasonal=False,  # No Seasonality
                              start_P=0,
                              D=0,  # Minimum differencing order
                              trace=False,
                              error_action='ignore',
                              suppress_warnings=True,
                              stepwise=True)
        output, conf_int = model.predict(n_periods=1, return_conf_int=True, alpha=args.alpha)
    except:
        pass
    if (real_value < conf_int[0][0] or real_value > conf_int[0][1]):
        return True
    return False


def check_feature_with_max(train, ground_truth):
    previous_max = np.max(np.asarray(train))
    if (ground_truth > previous_max):
        return True
    return False


def check_feature_single_val(previous_value, ground_truth):
    if (ground_truth > previous_value):
        return True
    return False


def extract_feature_before_and_after(features_series, nodes, time_step, args):
    # Check every node that is suspected
    for node in nodes:
        # Build dictionary that will contain boolean variables depending on the change in each feature
        attack_class_dict = {feature: False for feature in args.attack_classification_features}
        # Check every feature that must be checked to classify the attack
        for feature in args.attack_classification_features:
            # Get feature series
            feature_s = features_series[feature][node]
            # Check feature with different techniques
            if (feature == '# APP txd'):
                train = feature_s[time_step - 30: time_step]
                ground_truth = feature_s[time_step]
                attack_class_dict[feature] = check_feature_with_arima(train, ground_truth)
            if (feature == '# DIO txd'):
                train = feature_s[: time_step]
                ground_truth = feature_s[time_step]
                attack_class_dict[feature] = check_feature_with_max(train, ground_truth)
            if (feature == '# DIS txd'):
                previous_value = feature_s[time_step - 1]
                ground_truth = feature_s[time_step]
                attack_class_dict[feature] = check_feature_single_val(previous_value, ground_truth)
        # print('attack_class_dict: {}'.format(attack_class_dict))
        if (attack_class_dict['# DIS txd']):
            print('\tDevice {} -> DIS ATTACK!!!!!'.format(node))
        elif (attack_class_dict['# DIO txd']):
            print('\tDevice {} -> HELLO FLOODING ATTACK!!!!'.format(node))
        else:
            print('\tDevice {} -> False alarm'.format(node))


def check_communicating_nodes(net_traffic, time_step, list_nodes_train, anomalous_nodes, nodes_and_features_dict, args):
    # From original traffic get nodes communicating in this time window set
    condition = (net_traffic[args.time_feat_micro] > (time_step + 1) * args.time_window * 1e6) & (
            net_traffic[args.time_feat_micro] < (time_step + 2) * args.time_window * 1e6)
    data = net_traffic[condition]
    # Get list of nodes trasmitting at least 1 packet
    list_nodes = data['TRANSMITTER_ID'].value_counts().index.to_list()
    list_nodes = [node.split('-')[-1] for node in list_nodes if 'SENSOR' in node or 'SINKNODE' in node]
    list_nodes.sort()
    list_nodes_train.sort()
    # Check if this list is equal to the obtained during training, otherwise it's clone attack
    if (not (list_nodes == list_nodes_train)):
        nodes_missing = np.setdiff1d(list_nodes_train, list_nodes)
        for node in nodes_missing:
            nodes_and_features_dict[node]['# sensors'] = True
            print('\tDevice {} -> CLONE-ID or SYBIL ATTACK!!!!'.format(node))
            if node in anomalous_nodes:
                anomalous_nodes.remove(node)
    return anomalous_nodes, nodes_and_features_dict


def multiple_check_communicating_nodes(net_traffic, time_step, list_nodes_train, anomalous_nodes,
                                       nodes_and_features_dict, output_file, args):
    change_in_communicating_nodes = False
    # From original traffic get nodes communicating in this time window set
    mini_window = 3
    if args.simulation_tool == 'NetSim':
        for i in range(0, 10, mini_window):
            condition = (net_traffic[args.time_feat_sec] > ((time_step + 1) * args.time_window + i)) & (
                    net_traffic[args.time_feat_sec] < ((time_step + 1) * args.time_window + i + mini_window))
            data = net_traffic[condition]
            # Get list of nodes trasmitting at least 1 packet
            list_nodes = data['TRANSMITTER_ID'].value_counts().index.to_list()
            list_nodes = [node.split('-')[-1] for node in list_nodes if 'SENSOR' in node or 'SINKNODE' in node]
            list_nodes.sort()
            list_nodes_train.sort()
            # Check if this list is equal to the obtained during training, otherwise it's clone attack
            if (not (list_nodes == list_nodes_train)):
                change_in_communicating_nodes = True
                nodes_missing = np.setdiff1d(list_nodes_train, list_nodes)
                for node in nodes_missing:
                    nodes_and_features_dict[node]['# sensors'] = True
                    print('\tDevice {} -> CLONE-ID or SYBIL ATTACK!!!!'.format(node))
                    output_file.write('\tCLONE-ID or SYBIL ATTACK -> ATTACKER NODE: {}\n'.format(node))
                    if node in anomalous_nodes:
                        anomalous_nodes.remove(node)
                break
    else:
        condition = (net_traffic[args.time_feat_sec] > ((time_step + 1) * args.time_window)) & (
                net_traffic[args.time_feat_sec] < ((time_step + 2) * args.time_window))
        data = net_traffic[condition]
        # Get list of nodes trasmitting at least 1 packet
        list_nodes = data['TRANSMITTER_ID'].value_counts().index.to_list()
        list_nodes = [node.split('-')[-1] for node in list_nodes if 'SENSOR' in node]
        list_nodes.sort()
        if '1' in list_nodes_train:
            list_nodes_train.remove('1')
        list_nodes_train.sort()
        # Check if this list is equal to the obtained during training, otherwise it's clone attack
        if (not (list_nodes == list_nodes_train)):
            change_in_communicating_nodes = True
            nodes_missing = np.setdiff1d(list_nodes_train, list_nodes)
            for node in nodes_missing:
                nodes_and_features_dict[node]['# sensors'] = True
                print('\tDevice {} -> CLONE-ID or SYBIL ATTACK!!!!'.format(node))
                output_file.write('\tCLONE-ID or SYBIL ATTACK -> ATTACKER NODE: {}\n'.format(node))
                if node in anomalous_nodes:
                    anomalous_nodes.remove(node)
    return anomalous_nodes, nodes_and_features_dict, change_in_communicating_nodes


def get_ranks_in_window(control_traffic, time_step, anomalous_nodes, args, is_actual_ranks):
    # From original traffic get considered window
    condition = (control_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            control_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data = control_traffic[condition]
    names = data['RECEIVER_ID'].str.split('-', n=1, expand=True)
    data.drop(columns=['RECEIVER_ID'], inplace=True)
    all_ranks = {node_name: [] for node_name in anomalous_nodes}
    # If there is no change in ranks this window, return an empty list
    if len(data) != 0:
        data['RECEIVER_ID'] = names[1]
        # For each node get the list of ranks assumed in this time window
        for node_name in anomalous_nodes:
            ranks = data[data['RECEIVER_ID'] == node_name]['RPL_RANK'].value_counts().index.to_list()
            counter = 0
            # If this is "previous ranks", look further back in history if an empty list is returned
            while len(ranks) == 0 and not is_actual_ranks:
                counter +=1
                condition = (control_traffic[args.time_feat_sec] > (time_step + 1 - counter) * args.time_window) & (
                        control_traffic[args.time_feat_sec] < (time_step + 2 - counter) * args.time_window)
                data = control_traffic[condition]
                names = data['RECEIVER_ID'].str.split('-', n=1, expand=True)
                data.drop(columns=['RECEIVER_ID'], inplace=True)
                data['RECEIVER_ID'] = names[1]
                if len(data) != 0:
                    ranks = data[data['RECEIVER_ID'] == node_name]['RPL_RANK'].value_counts().index.to_list()
            all_ranks[node_name] = ranks
    return all_ranks

def compare_rank(rank_one, rank_two):
    # Return 0 if ranks are equivalent in regards to hops from root
    # Return -1 if rank_one is smaller than rank_two in regards to hops from root
    # Return 1 if rank_one is greater than rank_two in regards to hops from root
    diff = rank_one - rank_two
    if diff not in range(-127, 127):
        if diff < 0:
            return -1
        elif diff > 0:
            return 1
    return 0



def check_ranks_changed(previous_ranks, actual_ranks, nodes_and_features_dict, anomalous_nodes):
    change_in_ranks = False
    for node in anomalous_nodes:
        if node != '1':
            prev_ranks = previous_ranks[node]
            ac_ranks = actual_ranks[node]
            if len(ac_ranks) != 0:
                last_rank = prev_ranks[-1] # If these are in chronological order
                rank_changes = 0
                for rank in ac_ranks:
                    # I difference between ranks are >= 128 the rank has increased or decreased
                    diff = rank - last_rank
                    if compare_rank(rank, last_rank) != 0:
                        change_in_ranks = True
                        nodes_and_features_dict[node]['rank changed'] = True
                        rank_changes += 1
                    if len(ac_ranks) > 1:
                        last_rank = rank
                if rank_changes > 1:
                    nodes_and_features_dict[node]['rank changed more than once'] = True
                if len(ac_ranks) > 1 and compare_rank(ac_ranks[-1], ac_ranks[0]) == 1:
                    nodes_and_features_dict[node]['greater rank'] = True
                elif len(ac_ranks) > 1 and compare_rank(ac_ranks[-1], ac_ranks[0]) == -1:
                    nodes_and_features_dict[node]['smaller rank'] = True
                elif len(ac_ranks) == 1 and compare_rank(ac_ranks[0], prev_ranks[-1]) == 1:
                    nodes_and_features_dict[node]['greater rank'] = True
                elif len(ac_ranks) > 1 and compare_rank(ac_ranks[0], prev_ranks[-1]) == -1:
                    nodes_and_features_dict[node]['smaller rank'] = True
                # Possibly check for infinite rank?
    return nodes_and_features_dict, change_in_ranks


def check_n_nexthops(net_traffic, time_step, anomalous_nodes, nodes_and_features_dict, args):
    change_in_nexthops = False
    # Get data before anomaly is raised
    data_found = False
    i = 0
    while not data_found:
        condition = (net_traffic[args.time_feat_sec] < (time_step + 1) * args.time_window)
        data_before = net_traffic[condition]
        names = data_before['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
        data_before.drop(columns=['TRANSMITTER_ID'], inplace=True)
        if len(data_before) != 0:
            data_found = True
        i += 1
    data_before['TRANSMITTER_ID'] = names[1]
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            net_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data_after = net_traffic[condition]
    names = data_after['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['TRANSMITTER_ID'], inplace=True)
    if len(data_after) != 0:
        data_after['TRANSMITTER_ID'] = names[1]
        # Check each anomalous node if it has gained a next hop IP address (changing parent or destination)
        for node in anomalous_nodes:
            # Get number of next hops before anomaly
            all_transmitted_packets = data_before[data_before['TRANSMITTER_ID'] == node]
            if args.simulation_tool == 'NetSim':
                next_hop_ips = all_transmitted_packets[all_transmitted_packets['NEXT_HOP_IP'] != 'FF00:0:0:0:0:0:0:0'][
                    'NEXT_HOP_IP'].value_counts().index.to_list()
            else:
                next_hop_ips = all_transmitted_packets[all_transmitted_packets['NEXT_HOP_IP'] != 'ff02::1a'][
                    'NEXT_HOP_IP'].value_counts().index.to_list()
            dests_before = len(next_hop_ips)
            # Get number of next hops after anomaly
            all_transmitted_packets = data_after[data_after['TRANSMITTER_ID'] == node]
            if args.simulation_tool == 'NetSim':
                next_hop_ips = all_transmitted_packets[all_transmitted_packets['NEXT_HOP_IP'] != 'FF00:0:0:0:0:0:0:0'][
                    'NEXT_HOP_IP'].value_counts().index.to_list()
            else:
                next_hop_ips = all_transmitted_packets[all_transmitted_packets['NEXT_HOP_IP'] != 'ff02::1a'][
                    'NEXT_HOP_IP'].value_counts().index.to_list()
            dests_after = len(next_hop_ips)
            # If a new destination appears then change it in the conditions dictionary
            if (dests_after > dests_before):
                change_in_nexthops = True
                nodes_and_features_dict[node]['# next-hop IPs'] = True
    return nodes_and_features_dict, change_in_nexthops


def check_n_neighbors(net_traffic, time_step, anomalous_nodes, nodes_and_features_dict, args):
    # Get data before anomaly is raised
    condition = (net_traffic[args.time_feat_micro] < (time_step + 1) * args.time_window * 1e6)
    data_before = net_traffic[condition]
    names = data_before['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
    data_before.drop(columns=['TRANSMITTER_ID'], inplace=True)
    data_before['TRANSMITTER_ID'] = names[1]
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_micro] < (time_step + 2) * args.time_window * 1e6)
    data_after = net_traffic[condition]
    names = data_after['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['TRANSMITTER_ID'], inplace=True)
    data_after['TRANSMITTER_ID'] = names[1]
    # Check each anomalous node if it has gained a next hop IP address (changing parent or destination)
    for node in anomalous_nodes:
        # Get number of next hops before anomaly
        all_transmitted_packets = data_before[data_before['TRANSMITTER_ID'] == node]
        transmitted_dios = all_transmitted_packets[all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO']
        neighbors = transmitted_dios['RECEIVER_ID'].value_counts()
        neighbors_before = len(neighbors)
        # Get number of next hops after anomaly
        all_transmitted_packets = data_after[data_after['TRANSMITTER_ID'] == node]
        transmitted_dios = all_transmitted_packets[all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO']
        neighbors = transmitted_dios['RECEIVER_ID'].value_counts()
        neighbors_after = len(neighbors)
        # If a new destination appears then change it in the conditions dictionary
        if (neighbors_after > neighbors_before):
            nodes_and_features_dict[node]['# neighbors'] = True
    return nodes_and_features_dict


def check_versions(net_traffic, time_step, anomalous_nodes, nodes_and_features_dict, args):
    change_in_versions = False
    # Get data before anomaly is raised
    data_found = False
    counter = 0
    # If there is no data in previous window, fetch from next-last
    while not data_found:
        condition = (net_traffic[args.time_feat_sec] > (time_step) * args.time_window) & (
                net_traffic[args.time_feat_sec] < (time_step + 1) * args.time_window)
        data_before = net_traffic[condition]
        names = data_before['RECEIVER_ID'].str.split('-', n=1, expand=True)
        data_before.drop(columns=['RECEIVER_ID'], inplace=True)
        counter += 1
        if len(data_before) != 0:
            data_found = True
    data_before['RECEIVER_ID'] = names[1]
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            net_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data_after = net_traffic[condition]
    names = data_after['RECEIVER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['RECEIVER_ID'], inplace=True)
    if len(data_after) != 0:
        data_after['RECEIVER_ID'] = names[1]
        # Check each anomalous node if it has gained a next hop IP address (changing parent or destination)
        for node in anomalous_nodes:
            # Get number of next hops before anomaly
            all_transmitted_packets = data_before[data_before['RECEIVER_ID'] == node]
            condition = (all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO') | (
                    all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DAO') | (
                                all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIS')
            transmitted_controls = all_transmitted_packets[condition]
            versions_before = transmitted_controls['RPL_VERSION'].value_counts().index.to_list()
            # Get number of next hops after anomaly
            all_transmitted_packets = data_after[data_after['RECEIVER_ID'] == node]
            condition = (all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO') | (
                    all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DAO') | (
                                all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIS')
            transmitted_controls = all_transmitted_packets[condition]
            versions_after = transmitted_controls['RPL_VERSION'].value_counts().index.to_list()
            # If a new destination appears then change it in the conditions dictionary
            if (versions_after != versions_before and len(versions_after) != 0):
                change_in_versions = True
                nodes_and_features_dict[node]['version'] = True
    return nodes_and_features_dict, change_in_versions


def find_attacker_ranks(net_traffic, time_step, all_nodes, args):
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            net_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data_after = net_traffic[condition]
    names = data_after['RECEIVER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['RECEIVER_ID'], inplace=True)
    data_after['RECEIVER_ID'] = names[1]
    # Create dictionary with each node and corresponding time of rank change
    nodes_and_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get only DIOs transmitted by a single node
        all_transmitted_packets = data_after[data_after['RECEIVER_ID'] == node]
        condition = (all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO')
        transmitted_dios = all_transmitted_packets[condition]
        # Store smallest time in which rank changes
        first_change = math.inf
        for i in range(len(transmitted_dios.index) - 1):
            row_before = transmitted_dios.iloc[i]
            row_after = transmitted_dios.iloc[i + 1]
            rank_before = row_before['RPL_RANK']
            rank_after = row_after['RPL_RANK']
            if ((rank_after != rank_before) and not (math.isnan(rank_before)) and not (math.isnan(rank_after))):
                change_time = row_after[args.time_feat_sec]
                if (change_time < first_change):
                    first_change = change_time
        nodes_and_times_dict[node] = first_change
    # Check which node changed rank first
    min_change_time = math.inf
    attacker_node = []
    for node in all_nodes:
        if (nodes_and_times_dict[node] < min_change_time):
            min_change_time = nodes_and_times_dict[node]
            attacker_node = node
    if (attacker_node != []):
        print('Attacker node is {}. It changed rank at {}'.format(attacker_node, nodes_and_times_dict[attacker_node]))
    return attacker_node


def find_attacker_versions(net_traffic, time_step, all_nodes, args):
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            net_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data_after = net_traffic[condition]
    names = data_after['RECEIVER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['RECEIVER_ID'], inplace=True)
    data_after['RECEIVER_ID'] = names[1]
    # Create dictionary with each node and corresponding time of rank change
    nodes_and_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get only DIOs transmitted by a single node
        all_transmitted_packets = data_after[data_after['RECEIVER_ID'] == node]
        condition = (all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO')
        transmitted_dios = all_transmitted_packets[condition]
        # Store smallest time in which version changes
        first_change = math.inf
        for i in range(len(transmitted_dios.index) - 1):
            row_before = transmitted_dios.iloc[i]
            row_after = transmitted_dios.iloc[i + 1]
            version_before = row_before['RPL_VERSION']
            version_after = row_after['RPL_VERSION']
            if ((version_after != version_before) and not (math.isnan(version_before)) and not (
            math.isnan(version_after))):
                change_time = row_after[args.time_feat_sec]
                if (change_time < first_change):
                    first_change = change_time
        nodes_and_times_dict[node] = first_change
    # Check which node changed rank first
    min_change_time = math.inf
    attacker_node = []
    for node in all_nodes:
        if (nodes_and_times_dict[node] < min_change_time):
            min_change_time = nodes_and_times_dict[node]
            attacker_node = node
    if (attacker_node != []):
        print('Attacker node is {}. It changed rank at {}'.format(attacker_node, nodes_and_times_dict[attacker_node]))
    return attacker_node


def find_attacker_ranks_and_versions(net_traffic, time_step, all_nodes, args):
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            net_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data_after = net_traffic[condition]
    names = data_after['RECEIVER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['RECEIVER_ID'], inplace=True)
    data_after['RECEIVER_ID'] = names[1]
    # Create dictionary with each node and corresponding time of rank change and versions change
    nodes_and_ranks_times_dict = {node_name: math.inf for node_name in all_nodes}
    nodes_and_versions_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get only DIOs transmitted by a single node
        all_transmitted_packets = data_after[data_after['RECEIVER_ID'] == node]
        condition = (all_transmitted_packets['CONTROL_PACKET_TYPE/APP_NAME'] == 'DIO')
        transmitted_dios = all_transmitted_packets[condition]
        # Store smallest time in which version changes
        first_change_rank = math.inf
        first_change_version = math.inf
        for i in range(len(transmitted_dios.index) - 1):
            row_before = transmitted_dios.iloc[i]
            row_after = transmitted_dios.iloc[i + 1]
            version_before = row_before['RPL_VERSION']
            version_after = row_after['RPL_VERSION']
            rank_before = row_before['RPL_RANK']
            rank_after = row_after['RPL_RANK']
            if ((rank_after != rank_before) and not (math.isnan(rank_before)) and not (math.isnan(rank_after))):
                change_time_rank = row_after[args.time_feat_sec]
                if (change_time_rank < first_change_rank):
                    first_change_rank = change_time_rank
            if ((version_after != version_before) and not (math.isnan(version_before)) and not (
            math.isnan(version_after))):
                change_time_version = row_after[args.time_feat_sec]
                if (change_time_version < first_change_version):
                    first_change_version = change_time_version
        nodes_and_ranks_times_dict[node] = first_change_rank
        nodes_and_versions_times_dict[node] = first_change_version
    # Check which node changed rank first
    min_change_time_ranks = math.inf
    attacker_node_ranks = []
    for node in all_nodes:
        if (nodes_and_ranks_times_dict[node] < min_change_time_ranks):
            min_change_time_ranks = nodes_and_ranks_times_dict[node]
            attacker_node_ranks = node
    # Check which node changed version first
    min_change_time_versions = math.inf
    attacker_node_versions = []
    for node in all_nodes:
        if (nodes_and_versions_times_dict[node] < min_change_time_versions):
            min_change_time_versions = nodes_and_versions_times_dict[node]
            attacker_node_versions = node
    # Check if version or rank changed first
    attacker_node = []
    attack_type = []
    if (attacker_node_ranks != [] and attacker_node_versions == []):
        attacker_node = attacker_node_ranks[:]
        attack_type = 'RANK'
        print('RANK ATTACK! -> Attacker node is {}. It changed rank at {}'.format(attacker_node,
                                                                                  nodes_and_ranks_times_dict[
                                                                                      attacker_node]))
    if (attacker_node_ranks == [] and attacker_node_versions != []):
        attacker_node = attacker_node_versions[:]
        attack_type = 'VERSION'
        print('VERSION ATTACK! -> Attacker node is {}. It changed version at {}'.format(attacker_node,
                                                                                        nodes_and_versions_times_dict[
                                                                                            attacker_node]))
    if (attacker_node_ranks != [] and attacker_node_versions != []):
        if (attacker_node_versions[:] == '1') and (nodes_and_ranks_times_dict[attacker_node_ranks] < nodes_and_versions_times_dict[attacker_node_versions]):
            attacker_node = attacker_node_ranks[:]
            attack_type = 'RANK'
            print('RANK ATTACK! -> Attacker node is {}. It changed rank at {}'.format(attacker_node,
                                                                                      nodes_and_ranks_times_dict[
                                                                                          attacker_node]))
        else:
            attacker_node = attacker_node_versions[:]
            attack_type = 'VERSION'
            print('VERSION ATTACK! -> Attacker node is {}. It changed version at {}'.format(attacker_node,
                                                                                            nodes_and_versions_times_dict[
                                                                                                attacker_node]))
    return attacker_node, attack_type


def find_attacker_worst_parent(nodes_and_features_dict, list_nodes_train):
    attacker_nodes = []
    for node in list_nodes_train:
        if (nodes_and_features_dict[node]['# next-hop IPs']):
            attacker_nodes.append(node)
    return attacker_nodes

def classify_attack_from_dodag(features_series, all_packets, ranks_vers, apps_packets, anomalous_nodes, nodes_changing,
                               time_step, dodag_changed, list_nodes_train, dict_nodes_dests_from_train, output_file,
                               args):
    # Create list of features for attack classification
    all_features = args.attack_classification_features.copy()
    all_features.extend(['DODAG', '# sensors', '# next-hop IPs', '# neighbors', 'rank changed', 'rank changed once',
                         'rank changed more than once',
                         'smaller rank', 'greater rank', 'infinite rank', 'version', 'change_dest'])
    # Create dicts for nodes and anomalies
    nodes_and_features_dict = {node_name: {feature: False for feature in all_features} for node_name in
                               list_nodes_train}
    if '1' not in list_nodes_train:
        nodes_and_features_dict['1'] = {feature: False for feature in all_features}
    # Check if list of communicating nodes is equal to the list obtained from training
    tic = tm.perf_counter()
    anomalous_nodes, nodes_and_features_dict, change_in_communicating_nodes = multiple_check_communicating_nodes(
        all_packets, time_step, list_nodes_train, anomalous_nodes, nodes_and_features_dict, output_file, args)
    toc = tm.perf_counter()
    # Check if rank changed or not
    tic = tm.perf_counter()
    actual_ranks = get_ranks_in_window(ranks_vers, time_step, anomalous_nodes, args, True)
    if len(actual_ranks) > 0:
        data_found = False
        counter = 0
        while not data_found:
            previous_ranks = get_ranks_in_window(ranks_vers, time_step - counter - 1, anomalous_nodes, args, False)
            if len(previous_ranks) != 0:
                data_found = True
            counter += 1

        nodes_and_features_dict, change_in_ranks = check_ranks_changed(previous_ranks, actual_ranks,
                                                                   nodes_and_features_dict, anomalous_nodes)
    toc = tm.perf_counter()
    # Check number of next hops
    tic = tm.perf_counter()
    nodes_and_features_dict, change_in_nexthops = check_n_nexthops(all_packets, time_step, anomalous_nodes,
                                                                   nodes_and_features_dict, args)
    toc = tm.perf_counter()
    # Check versions
    tic = tm.perf_counter()
    nodes_and_features_dict, change_in_versions = check_versions(ranks_vers, time_step, anomalous_nodes,
                                                                 nodes_and_features_dict, args)
    toc = tm.perf_counter()

    # Set all nodes with corresponding dodag changed feature
    if (dodag_changed):
        for node in nodes_changing:
            nodes_and_features_dict[node]['DODAG'] = True
    # Check every node that is suspected
    for node in anomalous_nodes:
        # Check every feature that must be checked to classify the attack
        for feature_class in args.attack_classification_features:
            # Get feature series
            feature_s = features_series[feature_class][node]
            # Check feature with different techniques
            if (feature_class == '# APP txd' or feature_class == 'incoming_vs_outgoing'):
                train = feature_s[time_step - 30: time_step]
                ground_truth = feature_s[time_step]
                nodes_and_features_dict[node][feature_class] = check_feature_with_arima(train, ground_truth, args)
            if (feature_class == '# DIO txd'):
                train = feature_s[: time_step]
                ground_truth = feature_s[time_step]
                nodes_and_features_dict[node][feature_class] = check_feature_with_max(train, ground_truth)
            if (feature_class == '# DIS txd' or feature_class == '# next-hop IPs'):
                change_in_short_past = False
                for i in range(3):
                    previous_value = feature_s[time_step - i - 1]
                    ground_truth = feature_s[time_step - i]
                    if (check_feature_single_val(previous_value, ground_truth)):
                        change_in_short_past = True
                        break
                if (change_in_short_past):
                    nodes_and_features_dict[node][feature_class] = True

    if (not change_in_communicating_nodes):
        if (dodag_changed and (change_in_versions or change_in_ranks or change_in_nexthops)):
            if (change_in_ranks and change_in_versions):
                attacker_node, attack_type = find_attacker_ranks_and_versions(ranks_vers, time_step, list_nodes_train,
                                                                              args)
                print('\t{} ATTACK -> ATTACKER NODE {}'.format(attack_type, attacker_node))
                output_file.write('\t{} ATTACK -> ATTACKER NODE {}\n'.format(attack_type, attacker_node))
            elif (change_in_ranks and not change_in_versions):
                attacker_node = find_attacker_ranks(ranks_vers, time_step, list_nodes_train, args)
                print('\tRANKS ATTACKS -> ATTACKER NODE {}'.format(attacker_node))
                output_file.write('\tRANKS ATTACKS -> ATTACKER NODE {}\n'.format(attacker_node))
            elif (change_in_versions and not change_in_ranks):
                attacker_node = find_attacker_versions(ranks_vers, time_step, list_nodes_train, args)
                print('\tVERSION ATTACK -> ATTACKER NODE {}'.format(attacker_node))
                output_file.write('\tVERSION ATTACK -> ATTACKER NODE {}\n'.format(attacker_node))
            elif (change_in_nexthops):
                attacker_node = find_attacker_worst_parent(nodes_and_features_dict, list_nodes_train)
                print('\tWORST PARENT ATTACK -> ATTACKER NODE {}'.format(attacker_node))
                output_file.write('\tWORST PARENT ATTACK -> ATTACKER NODE {}\n'.format(attacker_node))
            else:
                print('\tNo change in ranks/version -> False alarm')
                output_file.write('\tFALSE ALARM\n')
        else:
            blackhole_attackers = []
            hello_flood_attackers = []
            dis_attackers = []
            for node in anomalous_nodes:
                if (nodes_and_features_dict[node]['# APP txd']):
                    if (nodes_and_features_dict[node]['incoming_vs_outgoing']):
                        print('\tDevice {} -> BLACKHOLE/SEL FORWARD ATTACK!!!!!'.format(node))
                        blackhole_attackers.append(node)
                    else:
                        print('\tDevice {} -> False alarm'.format(node))
                elif (nodes_and_features_dict[node]['# DIO txd']):
                    print('\tDevice {} -> HELLO FLOOD ATTACK!!!!!'.format(node))
                    hello_flood_attackers.append(node)
                elif (nodes_and_features_dict[node]['# DIS txd']):
                    print('\tDevice {} -> DIS ATTACK!!!!!'.format(node))
                    dis_attackers.append(node)
                else:
                    print('\tDevice {} -> False alarm'.format(node))

            # Print single line on output file
            if (blackhole_attackers != []):
                output_file.write('\tBLACKHOLE/SEL FORWARD ATTACK -> ATTACKER NODE {}\n'.format(blackhole_attackers))
            if (hello_flood_attackers != []):
                output_file.write('\tHELLO FLOOD ATTACK -> ATTACKER NODE {}\n'.format(hello_flood_attackers))
            if (dis_attackers != []):
                output_file.write('\tDIS ATTACK -> ATTACKER NODE {}\n'.format(dis_attackers))
            if (blackhole_attackers == [] and hello_flood_attackers == [] and dis_attackers == []):
                output_file.write('\tFALSE ALARM\n')


def extract_dios_up_to(data, time, args):
    # From the pandas dataframe extract only those packets arrived up to a certain second
    condition = (data[args.time_feat_sec] <= time)
    data = data[condition]
    return data


def extract_neighborhood(data, list_nodes, time, args):
    # Get all DIOs up to when the anomaly is raised
    dio_msgs = extract_dios_up_to(data, time, args)
    # For each nodes raising anomaly get correponding neighbours from DIOs
    neighborhood = list()
    for node in list_nodes:
        # Extract DIOs received by single node
        node_rcvd_dios = dio_msgs[dio_msgs['RECEIVER_ID'] == node]
        # Get corresponding transmitter
        transmitters = node_rcvd_dios['TRANSMITTER_ID'].unique()
        neighborhood.append(transmitters)
    # Create single list of neighbors and remove original nodes that raise anomalies from it
    neighborhood = [neighbor for sublist in neighborhood for neighbor in sublist]
    neighborhood = [neighbor for neighbor in neighborhood if neighbor not in list_nodes]
    neighborhood_short = [neighbor.split('-')[-1] for neighbor in neighborhood]
    # Get unique elements
    neighborhood = list(set(neighborhood))
    neighborhood_short = list(set(neighborhood_short))
    return neighborhood, neighborhood_short
