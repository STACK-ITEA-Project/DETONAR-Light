import csv
import os
import glob

import feature_extractor
import math
import numpy as np


path = "../dataset/16_Nodes_Dataset/Legit/Packet_Trace_3600s/101.csv"

class default_args:
    time_window = 60
    time_start = 60
    simulation_time = 3600
    path_to_file = path
    scenario = 'Legit'
    simulation = 'simulation-101'

def parse(args):
    features_list = ['# DIO rcvd', '# DIO txd', '# DAO txd', '# DIS txd', '# APP rcvd', '# APP txd',
                'incoming_vs_outgoing', 'parent_changed', '# ranks', 'version_changed', 'active']

    data = feature_extractor.get_data(os.path.join(os.getcwd(), '..',args.data_dir, args.scenario, 'Packet_Trace_{}s'.format(args.simulation_time), args.chosen_simulation+'.csv'))
    nodes_names = feature_extractor.get_unique_nodes_names(data)

    for node in nodes_names:
        with open('extended_features/{}/{}/{}/{}.csv'.format(args.scenario, args.simulation_time, 'simulation-'+args.chosen_simulation, node), 'w') as output_file:
            # Write column names to output file
            writer = csv.writer(output_file)
            writer.writerow(features_list)
            # Get all packets transmitted by node
            transmitted_condition = data['TRANSMITTER_ID'] == node
            transmitted_packets = data[transmitted_condition]
            # Get all packets received by node
            received_condition = data['RECEIVER_ID'] == node
            received_packets = data[received_condition]
            # Get all packets received or transmitted by node
            all_condition = (received_condition | transmitted_condition)
            all_packets = data[all_condition]
            # Get index for windowing the network traffic
            start_index = 0
            end_index = math.floor(args.simulation_time - args.time_start) / args.time_window
            matrix = []
            # For each index get the corresponding network traffic window and extract the features in that window
            for index in range(int(start_index), int(end_index)):
                features = np.zeros(len(features_list), dtype=float)
                # Get transmitted, received and all packets within the time window
                transmitted = feature_extractor.get_time_window_data(transmitted_packets, index, args, full_data=False)
                received = feature_extractor.get_time_window_data(received_packets, index, args, full_data=False)
                all_txd_and_rec = feature_extractor.get_time_window_data(all_packets, index, args, full_data=False)

                # Get the count of the different types of packets
                received_count = received['CONTROL_PACKET_TYPE/APP_NAME'].value_counts()
                transmitted_count = transmitted['CONTROL_PACKET_TYPE/APP_NAME'].value_counts()

                # Get number of DIO received
                features[0] = received_count['DIO'] if 'DIO' in received_count else 0
                # Get number of DIO transmitted
                features[1] = transmitted_count['DIO'] if 'DIO' in transmitted_count else 0
                # Get number of DAO transmitted
                features[2] = transmitted_count['DAO'] if 'DAO' in transmitted_count else 0
                # Get number of DIS transmitted
                features[3] = transmitted_count['DIS'] if 'DIS' in transmitted_count else 0
                # Get number of application packets received
                received_app_count = received['PACKET_TYPE'].value_counts()
                if 'Control_Packet' in received_app_count:
                    features[4] = received_app_count.sum() - received_app_count['Control_Packet']
                else:
                    features[4] = received_app_count.sum()
                # Get number of application packets transmitted
                transmitted_app_count = transmitted['PACKET_TYPE'].value_counts()
                if 'Control_Packet' in transmitted_app_count:
                    features[5] = transmitted_app_count.sum() - transmitted_app_count['Control_Packet']
                else:
                    features[5] = transmitted_app_count.sum()
                # Get number of incoming application packets that do not have itself as destination
                received_app_pcks = received[received['PACKET_TYPE'] == 'Sensing']
                incoming = received_app_pcks[(received_app_pcks['DESTINATION_ID'] != received_app_pcks['RECEIVER_ID']) & (
                            received_app_pcks['PACKET_STATUS'] == 'Successful')]
                n_incoming_app_pcks = len(incoming.index)
                # Get number of outgoing application packets that do not have itself as source
                transmitted_app_pcks = transmitted[transmitted['PACKET_TYPE'] == 'Sensing']
                outgoing = transmitted_app_pcks[
                    transmitted_app_pcks['SOURCE_ID'] != transmitted_app_pcks['TRANSMITTER_ID']]
                n_outgoing_app_pcks = len(outgoing.index)
                # Set nr of incoming vs outgoing
                if n_incoming_app_pcks == n_outgoing_app_pcks:
                    features[6] = 1
                elif n_outgoing_app_pcks != 0 and n_incoming_app_pcks == 0:
                    features[6] = 1
                else:
                    features[6] = n_outgoing_app_pcks / n_incoming_app_pcks  # * 100
                # Parent changed
                # In Cooja, parent == nexthop IP
                nexthops = transmitted['NEXT_HOP_IP'].value_counts().index.to_list()
                features[7] = len(nexthops)
                # Get nr of ranks
                ranks = transmitted['RPL_RANK'].value_counts().index.to_list()
                features[8] = len(ranks)
                # Get nr of versions
                versions = transmitted['RPL_VERSION'].value_counts().index.to_list()
                features[9] = len(versions)
                # Number of transmitted packets during this time window
                # This has to be changed later
                features[10] = len(transmitted)

                # Append the features row in feature file
                writer.writerow(features)
