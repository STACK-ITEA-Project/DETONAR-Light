# Python modules
import math
import time as tm
import warnings

import numpy as np
import pmdarima as pm

warnings.filterwarnings("ignore")


# Python files


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

def check_nodes_communicating(feature_series, time_step, list_nodes_train, anomalous_nodes,
                              nodes_and_features_dict, output_file, args):
    change_in_communicating_nodes = False
    nodes_missing = []

    for node in list_nodes_train:
        feature_sum_this_timestep = 0
        for feature in args.attack_classification_features:
            feature_sum_this_timestep += feature_series[feature][node][time_step]
        if feature_sum_this_timestep == 0:
            change_in_communicating_nodes = True
            nodes_missing.append(node)
    for node in nodes_missing:
        print('\tDevice {} -> CLONE-ID or SYBIL ATTACK!!!!'.format(node))
        output_file.write('\tCLONE-ID or SYBIL ATTACK -> ATTACKER NODE: {}\n'.format(node))
        if node in anomalous_nodes:
            anomalous_nodes.remove(node)
    return anomalous_nodes, nodes_and_features_dict, change_in_communicating_nodes

def multiple_check_communicating_nodes(features_series, time_step, list_nodes_train, anomalous_nodes,
                                       nodes_and_features_dict, output_file, args):
    change_in_communicating_nodes = False
    # From features series, get nodes communicating in this time window set
    #condition = (net_traffic[args.time_feat_sec] > ((time_step + 1) * args.time_window)) & (
    #        net_traffic[args.time_feat_sec] < ((time_step + 2) * args.time_window))

    condition = features_series[time_step]
    data = features_series[condition]
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

def check_ranks_br(features_series, nodes_and_features_dict, time_step, anomalous_nodes):
    change_in_ranks = False
    for node in anomalous_nodes:
        if node != 'SINKNODE-1':
            previous_rank = features_series['current_rank'][node][time_step - 1]
            actual_rank = features_series['current_rank'][node][time_step]
            rank_change_time = features_series['rank_change_time'][node][time_step]
            if rank_change_time > 0 and compare_rank(actual_rank, previous_rank) != 0:
                change_in_ranks = True
                nodes_and_features_dict[node]['rank changed'] = True
    return nodes_and_features_dict, change_in_ranks

def check_version_change(features_series, time_step, anomalous_nodes, nodes_and_features_dict, args):
    change_in_versions = False
    # Should maybe check if version is different from last timestep as well? or something
    for node in anomalous_nodes:
        previous_version = features_series['current_version'][node][time_step - 1]
        actual_version = features_series['current_version'][node][time_step]
        version_change_time = features_series['version_change_time'][node][time_step]
        if version_change_time > 0 and actual_version != previous_version: # TODO: is it enough with only "version_change_time >0"?
            change_in_versions = True
            nodes_and_features_dict[node]['version'] = True
    return nodes_and_features_dict, change_in_versions

def check_nexthops(features_series, time_step, anomalous_nodes, nodes_and_features_dict, args):
    change_in_nexthops = False
    for node in anomalous_nodes:
        # If the nr of next-hop IPs during the time window is > 1, a next-hop IP has been added
        if features_series['changed_parent'][node][time_step] > 1:
            change_in_nexthops = True
            nodes_and_features_dict[node]['parent_changed'] = True
    return nodes_and_features_dict, change_in_nexthops

def check_destination_change(features_series, time_step, anomalous_nodes, nodes_and_features_dict):
    change_in_destination = False
    nodes_changing_destination = []
    for node in anomalous_nodes:
        # Get nr of receivers for last step
        receivers_before = features_series['changed_parent'][node][time_step - 1]
        # Get nr of receivers for current step
        receivers_now = features_series['changed_parent'][node][time_step]
        # Is receivers the same as next hop in this case?
        if receivers_now > receivers_before:
            change_in_destination = True
            nodes_and_features_dict['change dest'] = True # Används inte
            nodes_changing_destination.append(node)
    if (change_in_destination):
        print('\tNODES CHANGING DESTINATION: {}'.format(nodes_changing_destination))
    return nodes_and_features_dict, change_in_destination, nodes_changing_destination

def find_attacker_ranks(feature_series, time_step, all_nodes, args):
    # Create dictionary with each node and corresponding time of rank change
    nodes_and_times_dict = {node_name: math.inf for node_name in all_nodes}
    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        # Get time of rank change (if any)
        rank_change_time = feature_series['rank_change_time'][node][time_step]
        if rank_change_time != 0:
            nodes_and_times_dict[node] = rank_change_time
    # Check which node changed rank first
    min_change_time = math.inf
    attacker_node = []
    for node in all_nodes:
        if (nodes_and_times_dict[node] < min_change_time):
            min_change_time = nodes_and_times_dict[node]
            if len(attacker_node) == 0:
                attacker_node.append(node)
            else:
                attacker_node[0] = node
    if (attacker_node != []):
        print('Attacker node is {}. It changed rank at {}'.format(attacker_node, nodes_and_times_dict[attacker_node[0]]))
    return attacker_node


def find_attacker_versions(feature_series, time_step, all_nodes, args):
    # Create dictionary with each node and corresponding time of rank change
    nodes_and_times_dict = {node_name: math.inf for node_name in all_nodes}

    # For each node check when it changed advised new version for the first time
    for node in all_nodes:
        version_change_time = feature_series['version_change_time'][node][time_step]
        if version_change_time != 0:
            nodes_and_times_dict[node] = version_change_time

    # Check which node changed version first
    min_change_time = math.inf
    attacker_node = []
    for node in all_nodes:
        if node != 'SINKNODE-1':
            if (nodes_and_times_dict[node] < min_change_time):
                min_change_time = nodes_and_times_dict[node]
                if len(attacker_node) == 0:
                    attacker_node.append(node)
                else:
                    attacker_node[0] = node
    if (attacker_node != []):
        print('Attacker node is {}. It changed rank at {}'.format(attacker_node, nodes_and_times_dict[attacker_node[0]]))
    attacker = []
    attacker.append(attacker_node)
    return attacker


def find_attacker_ranks_and_versions(feature_series, time_step, all_nodes, args):
    # Create dictionary with each node and corresponding time of rank change and versions change
    nodes_and_ranks_times_dict = {node_name: math.inf for node_name in all_nodes}
    nodes_and_versions_times_dict = {node_name: math.inf for node_name in all_nodes}

    # For each node check when it changed advised rank for the first time
    for node in all_nodes:
        rank_change_time = feature_series['rank_change_time'][node][time_step]
        version_change_time = feature_series['version_change_time'][node][time_step]
        if rank_change_time != 0:
            nodes_and_ranks_times_dict[node] = rank_change_time
        if node != 'SINKNODE-1':
            if version_change_time != 0:
                nodes_and_versions_times_dict[node] = version_change_time

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
    attacker = []
    attacker.append(attacker_node)
    return attacker, attack_type


def find_attacker_worst_parent(nodes_and_features_dict, list_nodes_train):
    attacker_nodes = []
    for node in list_nodes_train:
        if (nodes_and_features_dict[node]['parent_changed']):
            attacker_nodes.append(node)
    return attacker_nodes
def classify_attack_from_dodag(features_series, active, anomalous_nodes, nodes_changing,
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
    if 'SINKNODE-1' not in list_nodes_train:
        nodes_and_features_dict['SINKNODE-1'] = {feature: False for feature in all_features}
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
    nodes_and_features_dict, change_in_ranks = check_ranks_br(features_series, nodes_and_features_dict, time_step,
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
            if (feature_class == '# DIS txd' or feature_class == 'parent_changed'):
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
                attacker_node, attack_type = find_attacker_ranks_and_versions(features_series, time_step, list_nodes_train,
                                                                              args)
                print('\t{} ATTACK -> ATTACKER NODE {}'.format(attack_type, attacker_node))
                output_file.write('\t{} ATTACK -> ATTACKER NODE {}\n'.format(attack_type, attacker_node))
            elif (change_in_ranks and not change_in_versions):
                attacker_node = find_attacker_ranks(features_series, time_step, list_nodes_train, args)
                print('\tRANKS ATTACK -> ATTACKER NODE {}'.format(attacker_node))
                output_file.write('\tRANKS ATTACK -> ATTACKER NODE {}\n'.format(attacker_node))
            elif (change_in_versions and not change_in_ranks):
                attacker_node = find_attacker_versions(features_series, time_step, list_nodes_train, args)
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


def extract_packets_up_to(data, time, args):
    # From the pandas dataframe extract only those packets arrived up to a certain second
    condition = (data[args.time_feat_sec] <= time)
    data = data[condition]
    return data

def get_time_step_from_time(time,args):
    # Time in seconds
    return math.floor((time - args.time_start) / args.time_window)

def extract_neighborhood(data, list_nodes, time, args):
    # For each node raising anomaly get correponding neighbours from neighbor-file
    neighborhood = list()
    for node in list_nodes:
        neighborhood.append(data[node][get_time_step_from_time(time, args)])
    '''
    for node in list_nodes:
        # Extract DIOs received by single node
        node_rcvd_dios = dio_msgs[dio_msgs['RECEIVER_ID'] == node]
        # Get corresponding transmitter
        transmitters = node_rcvd_dios['TRANSMITTER_ID'].unique()
        neighborhood.append(transmitters)
    '''
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
