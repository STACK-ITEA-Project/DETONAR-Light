import csv
import math
import os
import numpy as np
import pandas as pd
import ast


class Args:
    time_window = None
    time_start = None
    simulation_time = None
    scenario = None
    simulation_tool = None
    chosen_simulation = None
    data_dir = None
    time_feat_seconds = None
    time_feat_micro = None
    max_nr_neighbors = None
    def __init__(self):
        self.simulation_time = 32400
        self.time_window = 600
        self.time_start = 600
        self.data_dir = 'dataset/test_dataset'
        self.simulation_tool = 'Cooja'
        self.output_dir = 'output/{}s{}w{}'
        self.feat_folder = 'log/features_extracted/'
        self.chosen_simulation = '00001'
        self.time_feat_micro = 'TIME'
        self.time_feat_seconds = 'TIME'
        self.scenario = 'Blackhole'
        self.max_nr_neighbors = 15



def get_data(path_to_file):
    # Read csv file
    data = pd.read_csv(path_to_file, index_col=False)
    # For each column check if it contains a time value in micro seconds, if so bring it to seconds
    for column in data.columns:
        if ('US' in column): # TODO: should this be done for column TIME???
            # Sometimes time values are cut due to NetSim simulator so we need to replace them with nan values
            if (data[column].dtype == object):
                data[column] = data[column].replace('N', np.nan, regex=True)
                data[column] = data[column].replace('Na', np.nan, regex=True)
                data[column] = data[column].replace('', np.nan, regex=True)
                data[column] = pd.to_numeric(data[column])
            data[column] = data[column] / 1e6
    return data

def get_unique_nodes_names(data):
    # Get names of transmitter devices
    nodes_names = data['SENDER_ID'].unique()
    # Remove nan values
    nodes_names = [i for i in nodes_names if str(i) != 'nan']
    # Remove nodes that are not sensors
    nodes_names = [i for i in nodes_names if ('SENSOR' in i or 'SINKNODE' in i)]
    return nodes_names

def get_time_window_data(data, index, args, full_data=False): # TODO: Rätt sätt att hämta ut data från tidsfönstret
    time_window = args.time_window
    if (full_data):
        start_time = 0 # TODO: was "time_start * 1e6"
    else:
        start_time = (index * time_window) * 1e6 # TODO: was index * time_window + "time_start * 1e6"
    end_time = ((index + 1) * time_window) * 1e6 # TODO: was index * time_window + "time_start * 1e6"
    # Get all packets that have been received at the network layer between start and end time (depending on window size)
    condition = (data[args.time_feat_micro] > start_time) & (data[args.time_feat_micro] <= end_time)
    sequence = data[condition]
    return sequence

def parse_stats(args):
    features_list = ['# DIO rcvd', '# APP rcvd', '# DAO txd','# DIO txd', '# DIS txd',  '# APP txd', 'incoming_vs_outgoing',
                '# ranks', 'version_changed', 'current_rank', 'current_version', 'nr_neighbors', 'neighbors']

    data = get_data(os.path.join(os.getcwd(), '..', args.data_dir, args.scenario, 'Packet_Trace_{}s'.format(args.simulation_time), args.chosen_simulation+'_stats.csv'))
    nodes_names = get_unique_nodes_names(data)

    active_dict = {time_step: [] for time_step in range(int(args.simulation_time/args.time_window))}

    for node in nodes_names:
        if(not os.path.exists('extended_features/{}/{}/{}'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation))):
            os.makedirs('extended_features/{}/{}/{}'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation))
        neighbor_list = []
        with open('extended_features/{}/{}/{}/{}_{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, node, 'stats'), 'w') as output_file:
            # Write column names to output file
            writer = csv.writer(output_file)
            writer.writerow(features_list)
            # Get all packets transmitted by node
            id_condition = data['SENDER_ID'] == node
            stats_packets = data[id_condition]
            # Get index for windowing the network traffic
            start_index = 0
            end_index = math.floor(args.simulation_time) / args.time_window
            # For each index get the corresponding network traffic window and extract the features in that window
            for index in range(int(start_index), int(end_index)):
                node_communicating_during_time_window = False
                features = np.zeros(len(features_list), dtype=float)
                neighbors = []
                # Get transmitted, received and all packets within the time window
                stats = get_time_window_data(stats_packets, index, args, full_data=False)
                if stats.empty:
                    # Node didn't send any packets in this time window
                    active_dict[index].append(False)
                    break
                else:
                    active_dict[index].append(True)
                    # Get number of DIO received
                    features[0] = stats['DIO_rcvd'].sum()
                    # Get number of DIO transmitted
                    features[1] = stats['APP_rcvd'].sum()
                    # Get number of DAO transmitted
                    features[2] = stats['DAO_txd'].sum()
                    # Get number of DIS transmitted
                    features[3] = stats['DIO_txd'].sum()
                    # Get number of application packets received
                    features[4] = stats['DIS_txd'].sum()
                    # Get number of application packets transmitted
                    features[5] = stats['APP_txd'].sum()
                    # Set nr of incoming vs outgoing
                    nr_incoming = stats['APP_rcvd'].sum()
                    nr_outgoing = stats['APP_txd'].sum()
                    if nr_incoming == nr_outgoing:
                        features[6] = 1
                    elif nr_outgoing != 0 and nr_incoming == 0:
                        features[6] = 1
                    else:
                        features[6] = nr_outgoing / nr_incoming
                    # Rank changed
                    features[7] = stats['RANK_CHANGED'].sum()
                    # Version changed
                    features[8] = stats['VERSION_CHANGED'].sum()
                    # Current rank
                    features[9] = stats['CURRENT_RANK'].iat[-1]
                    # Current version
                    features[10] = stats['CURRENT_VERSION'].iat[-1]
                    # Nr of neighbors
                    features[11] = stats['NR_NEIGHBORS'].sum() # TODO: Detta måste göra på något annat sätt. pga det kan vara samma neighbors? Hur?
                    # List of neighbors
                    for i in range(len(stats['NEIGHBORS'])):
                        nbrs = ast.literal_eval(list(stats['NEIGHBORS'])[i])

                        for j in range(len(nbrs)):
                            neighbors.append(nbrs[j])
                neighbor_list.append(neighbors)
                # Append the features row in feature file
                writer.writerow(features)

        # Create file from active-dict
        with open('extended_features/{}/{}/{}/{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, 'active'), 'w') as active_file:
            writer = csv.writer(active_file)
            writer.writerow(nodes_names)
            writer.writerows(active_dict.values())

        # Create neighbors-file for each node
        with open('extended_features/{}/{}/{}/{}_{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, node, 'neighbors'), 'w') as neighbor_file:
            writer = csv.writer(neighbor_file)
            columns_neighbors = [i for i in range(args.max_nr_neighbors)]
            writer.writerow(columns_neighbors)
            for neighbors in neighbor_list:
                neighbors = list(set(neighbors))
                row = np.zeros(args.max_nr_neighbors, dtype=float)
                for i in range(len(columns_neighbors)):
                    if i < len(neighbors):
                        row[i] = str(neighbors[i])
                    else:
                        row[i] = 0
                writer.writerow(row)

        # Create dao-file for each node TODO: Probably not needed?
        with open('extended_features/{}/{}/{}/{}_{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, node, 'dao'), 'w') as dao_file:
            writer = csv.writer(dao_file)
            columns_daos = ['TIME', 'PACKET_TYPE', 'CONTROL_PACKET_TYPE/APP_NAME', 'SOURCE_ID', 'DESTINATION_ID',
                            'PARENT_ID', 'SOURCE_IP', 'DESTINATION_IP', 'PARENT_IP']
            all_daos = get_data(
            os.path.join(os.getcwd(), '..', args.data_dir, args.scenario, 'Packet_Trace_{}s'.format(args.simulation_time),
                 args.chosen_simulation + '_dao.csv'))

            # Get all daos transmitted by node
            id_condition = all_daos['SOURCE_ID'] == node
            daos = all_daos[id_condition]
            daos.to_csv(dao_file, index=False)

        # Create a file of all DAOs sent
        with open('extended_features/{}/{}/{}/{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, 'all_DAOs'), 'w') as daos_file:
            writer = csv.writer(daos_file)
            columns_daos = ['TIME', 'PACKET_TYPE', 'CONTROL_PACKET_TYPE/APP_NAME', 'SOURCE_ID', 'DESTINATION_ID',
                            'PARENT_ID', 'SOURCE_IP', 'DESTINATION_IP', 'PARENT_IP']
            all_daos = get_data(
            os.path.join(os.getcwd(), '..', args.data_dir, args.scenario, 'Packet_Trace_{}s'.format(args.simulation_time),
                 args.chosen_simulation + '_dao.csv'))

            all_daos.to_csv(daos_file, index=False)


        # Create column of whether node changed parent for timestep or not
        columns = ['changed_parent']
        changed_parent = [0 for i in range(int(args.simulation_time/args.time_window))]
        last_parent_id = ""
        for row in daos.iterrows():
            parent = row[-1]['PARENT_ID']
            if not parent == last_parent_id:
                time = row[-1]['TIME'] # TODO: Is this the correct timestep?
                time_step = int((time/1e6)/args.time_window)
                changed_parent[time_step] = 1
            last_parent_id = row[-1]['PARENT_ID']
        stats_csv = pd.read_csv('extended_features/{}/{}/{}/{}_{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, node, 'stats'), index_col=False)
        stats_csv.insert(13, 'changed_parent', changed_parent)
        stats_csv.to_csv('extended_features/{}/{}/{}/{}_{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, node, 'stats'))



def main(args = Args()):
    parse_stats(args)


if __name__ == '__main__':
    main()