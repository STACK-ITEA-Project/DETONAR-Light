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
def check_nodes_communicating(features_series, time_step, list_nodes_train, anomalous_nodes,
                              nodes_and_features_dict, output_file, args):
    change_in_communicating_nodes = False
    nodes_missing = []

    for node in list_nodes_train:
        node_name = node
        feature_s = features_series['active'][node.split('-')[-1]]
        # This has to be changed.
        if feature_s[time_step] == 0:
            change_in_communicating_nodes = True
            nodes_missing.append(node_name)
    for node in nodes_missing:
        print('\tDevice {} -> CLONE-ID or SYBIL ATTACK!!!!'.format(node))
        output_file.write('\tCLONE-ID or SYBIL ATTACK -> ATTACKER NODE: {}\n'.format(node))
        if node in anomalous_nodes:
            anomalous_nodes.remove(node)
    return anomalous_nodes, nodes_and_features_dict, change_in_communicating_nodes

def check_ranks(features_series, nodes_and_features_dict, time_step, anomalous_nodes):
    change_in_ranks = False
    # Should maybe check if rank is different from last timestep as well?
    for node in anomalous_nodes:
        # # ranks
        if features_series['# ranks'][node.split('-')[-1]][time_step] > 1:
            change_in_ranks = True
            nodes_and_features_dict[node]['rank changed'] = True

    return nodes_and_features_dict, change_in_ranks

def check_nexthops(features_series, time_step, anomalous_nodes, nodes_and_features_dict, args):
    change_in_nexthops = False
    for node in anomalous_nodes:
        # If the nr of next-hop IPs during the time window is > 1, a next-hop IP has been added
        if features_series['parent_changed'][node.split('-')[-1]][time_step] > 1:
            change_in_nexthops = True
            nodes_and_features_dict[node]['parent_changed'] = True

    return nodes_and_features_dict, change_in_nexthops

def check_version_change(features_series, time_step, anomalous_nodes, nodes_and_features_dict, args):
    change_in_versions = False
    # Should maybe check if version is different from last timestep as well?
    for node in anomalous_nodes:
        if features_series['version_changed'][node.split('-')[-1]][time_step] > 0:
            change_in_versions = True
            nodes_and_features_dict[node]['version'] = True

    return nodes_and_features_dict, change_in_versions

def check_destination_change(features_series, time_step, anomalous_nodes, nodes_and_features_dict):
    change_in_destination = False
    nodes_changing_destination = []
    for node in anomalous_nodes:
        # Get nr of receivers for last step
        receivers_before = features_series['parent_changed'][node.split('-')[-1]][time_step - 1]
        # Get nr of receivers for current step
        receivers_now = features_series['parent_changed'][node.split('-')[-1]][time_step]
        # Is receivers the same as next hop in this case?
        if receivers_now > receivers_before:
            change_in_destination = True
            nodes_and_features_dict['change dest'] = True # Används inte
            nodes_changing_destination.append(node)
    if (change_in_destination):
        print('\tNODES CHANGING DESTINATION: {}'.format(nodes_changing_destination))
    return nodes_and_features_dict, change_in_destination, nodes_changing_destination

def find_attacker_ranks(net_traffic, time_step, all_nodes, args):
    # Get data after the anomaly
    condition = (net_traffic[args.time_feat_sec] > (time_step + 1) * args.time_window) & (
            net_traffic[args.time_feat_sec] < (time_step + 2) * args.time_window)
    data_after = net_traffic[condition]
    names = data_after['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['TRANSMITTER_ID'], inplace=True)
    data_after['TRANSMITTER_ID'] = names[1]
    # Create dictionary with each node and corresponding time of rank change
    nodes_and_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get only DIOs transmitted by a single node
        all_transmitted_packets = data_after[data_after['TRANSMITTER_ID'] == node]
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
    names = data_after['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['TRANSMITTER_ID'], inplace=True)
    data_after['TRANSMITTER_ID'] = names[1]
    # Create dictionary with each node and corresponding time of rank change
    nodes_and_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get only DIOs transmitted by a single node
        all_transmitted_packets = data_after[data_after['TRANSMITTER_ID'] == node]
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
    names = data_after['TRANSMITTER_ID'].str.split('-', n=1, expand=True)
    data_after.drop(columns=['TRANSMITTER_ID'], inplace=True)
    data_after['TRANSMITTER_ID'] = names[1]
    # Create dictionary with each node and corresponding time of rank change and versions change
    nodes_and_ranks_times_dict = {node_name: math.inf for node_name in all_nodes}
    nodes_and_versions_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get only DIOs transmitted by a single node
        all_transmitted_packets = data_after[data_after['TRANSMITTER_ID'] == node]
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
        if (nodes_and_ranks_times_dict[attacker_node_ranks] < nodes_and_versions_times_dict[attacker_node_versions]):
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
        if (nodes_and_features_dict[node]['parent_changed']):
            attacker_nodes.append(node)
    return attacker_nodes

def classify_attack_from_dodag(features_series, anomalous_nodes, nodes_changing,
                               time_step, dodag_changed, list_nodes_train, output_file,
                               args):
    # Create list of features for attack classification
    all_features = args.attack_classification_features.copy()
    all_features.extend(['DODAG', '# sensors', 'parent_changed', '# neighbors', 'rank changed', 'rank changed once',
                         'rank changed more than once', 'smaller rank', 'greater rank', 'infinite rank', 'version',
                         'change_dest'])
    # Create dicts for nodes and anomalies
    nodes_and_features_dict = {node_name: {feature: False for feature in all_features} for node_name in
                               list_nodes_train}
    # Check if list of communicating nodes is equal to the list obtained from training
    tic = tm.perf_counter()
    '''
    Check communicating nodes another way. if node sent statistics, it is still communicating
    '''
    anomalous_nodes, nodes_and_features_dict, change_in_communicating_nodes = check_nodes_communicating(features_series,
                    time_step, list_nodes_train, anomalous_nodes, nodes_and_features_dict, output_file, args)
    toc = tm.perf_counter()
    # Check if rank changed or not
    tic = tm.perf_counter()
    nodes_and_features_dict, change_in_ranks = check_ranks(features_series, nodes_and_features_dict, time_step,
                                                           anomalous_nodes)
    toc = tm.perf_counter()
    # Check number of next hops
    tic = tm.perf_counter()
    nodes_and_features_dict, change_in_nexthops = check_nexthops(features_series, time_step, anomalous_nodes,
                                                                   nodes_and_features_dict, args)
    toc = tm.perf_counter()
    # Check versions
    tic = tm.perf_counter()
    nodes_and_features_dict, change_in_versions = check_version_change(features_series, time_step, anomalous_nodes,
                                                                 nodes_and_features_dict, args)
    toc = tm.perf_counter()
    # Check destinations and DAOs
    tic = tm.perf_counter()
    nodes_and_features_dict, change_in_destination, nodes_changing_destination = check_destination_change(features_series,
                                                                    time_step, anomalous_nodes, nodes_and_features_dict)
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
            feature_s = features_series[feature_class][node.split('-')[-1]]
            # Check feature with different techniques
            if (feature_class == '# APP txd' or feature_class == 'incoming_vs_outgoing'):
                train = feature_s[time_step - 30: time_step]
                ground_truth = feature_s[time_step]
                nodes_and_features_dict[node][feature_class] = check_feature_with_arima(train, ground_truth, args)
            if (feature_class == '# DIO txd'):
                train = feature_s[: time_step]
                ground_truth = feature_s[time_step]
                nodes_and_features_dict[node][feature_class] = check_feature_with_max(train, ground_truth)
            if (feature_class == '# DIS txd' or feature_class == 'parent_changed'):
                change_in_short_past = False
                for i in range(int(args.time_window / 2)):
                    previous_value = feature_s[time_step - i - 1]
                    ground_truth = feature_s[time_step - i]
                    if (check_feature_single_val(previous_value, ground_truth)):
                        change_in_short_past = True
                        break
                if (change_in_short_past):
                    nodes_and_features_dict[node][feature_class] = True

    if (not change_in_communicating_nodes):
        if (dodag_changed):
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
            blackhole_attackers = []
            wormhole_attackers = []
            hello_flood_attackers = []
            dis_attackers = []
            for node in anomalous_nodes:
                if (nodes_and_features_dict[node]['# APP txd']):
                    if (nodes_and_features_dict[node]['incoming_vs_outgoing']):
                        print('\tDevice {} -> BLACKHOLE/SEL FORWARD ATTACK!!!!!'.format(node))
                        blackhole_attackers.append(node)
                    elif (change_in_destination and node in nodes_changing_destination):
                        print('\tDevice {} -> WORMHOLE ATTACK!!!!!'.format(node))
                        wormhole_attackers.append(node)
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
            if (wormhole_attackers != []):
                output_file.write('\tWORMHOLE ATTACK -> ATTACKER NODE {}\n'.format(wormhole_attackers))
            if (hello_flood_attackers != []):
                output_file.write('\tHELLO FLOOD ATTACK -> ATTACKER NODE {}\n'.format(hello_flood_attackers))
            if (dis_attackers != []):
                output_file.write('\tDIS ATTACK -> ATTACKER NODE {}\n'.format(dis_attackers))
            if (blackhole_attackers == [] and wormhole_attackers == [] and hello_flood_attackers == [] and dis_attackers == []):
                output_file.write('\tFALSE ALARM\n')


def extract_packets_up_to(data, time, args):
    # From the pandas dataframe extract only those packets arrived up to a certain second
    condition = (data[args.time_feat_sec] <= time)
    data = data[condition]
    return data


def extract_neighborhood(data, list_nodes, time, args):
    # Get all DIOs up to when the anomaly is raised
    dio_msgs = extract_packets_up_to(data, time, args)
    # For each node raising anomaly get correponding neighbours from DIOs
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

def extract_family(daos, anomalous_nodes, time, args):
    # In RADAR, DAOs are sent to parent. In Cooja, DAOs are sent to root

    # Get all DAOs up to when the anomaly is raised
    dao_msgs = extract_packets_up_to(daos, time, args)
    # For each node raising anomaly get correponding parent
    neighborhood = list()
    for node in anomalous_nodes:
        if args.simulation_tool == 'NetSim':
            # Extract all DAOs either transmitted or received by node
            node_rcvd_daos = dao_msgs[dao_msgs['RECEIVER_ID'] == node]
            node_txd_daos = dao_msgs[dao_msgs['TRANSMITTER_ID'] == node]
            # Get corresponding transmitter/receiver
            transmitters = node_rcvd_daos['TRANSMITTER_ID'].unique()
            receivers = node_rcvd_daos['RECEIVER_ID'].unique()
            for transmitter in transmitters:
                neighborhood.append(transmitter)
            for receiver in receivers:
                neighborhood.append(receiver)
        else:
            # Check the nexthop-ip for node, to simulate the gateway knows which parents a node as haf
            node_txd_daos = dao_msgs[dao_msgs['SOURCE_ID'] == node]
            parents = node_txd_daos['RECEIVER_ID'].unique()
            for parent in parents:
                 neighborhood.append(parent)

    # Create single list of neighbors and remove original nodes that raise anomalies from it
    new_list = []
    for neighbor in neighborhood:
        if neighbor not in new_list:
            new_list.append(neighbor)
    new_neighborhood = [neighbor for neighbor in new_list if neighbor not in anomalous_nodes]
    neighborhood_short = [neighbor.split('-')[-1] for neighbor in neighborhood]
    # Get unique elements
    neighborhood = list(set(neighborhood))
    neighborhood_short = list(set(neighborhood_short))
    return neighborhood, neighborhood_short

def extract_non_anomalous_nodes(all_nodes, nodes_raising_anomaly_full_name):
    # Add all nodes to the neighborhood
    neighborhood = list()
    for node in all_nodes:
        neighborhood.append(node)
    # Create single list of neighbors and remove original nodes that raise anomalies from it
    neighborhood = [neighbor for neighbor in neighborhood if neighbor not in nodes_raising_anomaly_full_name]
    neighborhood_short = [neighbor.split('-')[-1] for neighbor in neighborhood]
    # Get unique elements
    neighborhood = list(set(neighborhood))
    neighborhood_short = list(set(neighborhood_short))
    return neighborhood, neighborhood_short
