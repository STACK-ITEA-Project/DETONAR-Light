import os
import datetime
import glob

scenarios = ['Legit', 'Blackhole', 'Sinkhole', 'BlackholeAndSinkhole']
sim_time = "25200"
time_window = "600"
#data_dir = "dataset/16_Nodes_Dataset"
data_dir = "dataset/16_Nodes_Cooja"
simulation_tool = "Cooja"
output_dir = "output/{}s{}w{}"
feat_folder = 'log/features_extracted/'


output_filename = os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today()))
result_file = open(output_filename, 'w')

for scenario in scenarios:
    #if os.path.exists(os.path.join(os.getcwd(), 'log', output_dir.format(sim_time, time_window,datetime.date.today()), scenario)):
    #    filenames = glob.glob(os.path.join(os.getcwd(), 'log', output_dir.format(sim_time, time_window, datetime.date.today()), scenario, '*'))

    if os.path.exists(os.path.join(os.getcwd(), 'log', output_dir.format(sim_time, time_window,"2022-10-24"), scenario)):
        filenames = glob.glob(os.path.join(os.getcwd(), 'log', output_dir.format(sim_time, time_window, "2022-10-24"), scenario, '*'))

        result_file.write('{}\n'.format(scenario))
        for file in filenames:
            f = open(file, 'r')
            lines = f.readlines()

            # Get last part of path
            filename = file.split('/')[-1]
            # Remove filetype
            sim_number = filename.split('.')[0]
            attack_dict = {'BLACKHOLE/SEL FORWARD': [[],[]], 'CLONE-ID or SYBIL': [[],[]], 'DIS': [[],[]], 'HELLO FLOOD': [[],[]], 'RANKS': [[],[]],
             'VERSION': [[],[]], 'WORMHOLE': [[],[]], 'WORST PARENT': [[],[]]}
            times_list = []
            for line in lines:
                if 'ATTACK' in line:
                    attack_messy, attacker_node = line.split('ATTACK ->')
                    attack = attack_messy.lstrip().rstrip()
                    nodes = attacker_node.split('[')[-1].split(']')[0].rstrip().lstrip() # tex '7' eller '8','3','2'
                    if ',' in nodes:
                        nodes = nodes.split(',')
                    else:
                        single_node = nodes
                        nodes = []
                        nodes.append(single_node)
                    if 'ATTACK' in last_line:
                        time = last_time
                    else:
                        first, second = last_line.split('time')
                        time = last_line.split('time')[-1].split('.0. Devices')[0].rstrip().lstrip()
                    attack_dict[attack][0].append(time)
                    if len(nodes) == 1:
                        clean_node = nodes[0].split('\'')[1]
                        attack_dict[attack][1].append(clean_node)
                    else:
                        for node in nodes:
                            clean_node = node.split('\'')[1]
                            if clean_node not in attack_dict[attack][1]:
                                attack_dict[attack][1].append(clean_node)
                else:
                    time = 0
                last_time = time
                last_line = line
            str = ""
            for attack in attack_dict:
                if len(attack_dict[attack][0]) > 0:
                    times_str = ""
                    for el in attack_dict[attack][0]:
                        if el != attack_dict[attack][0][0]:
                            times_str = times_str +', '
                        times_str = times_str + el
                    nodes_str = ""
                    attack_dict[attack][1].sort(key=int)
                    for node in attack_dict[attack][1]:
                        if node != attack_dict[attack][1][0]:
                            nodes_str = nodes_str +', '
                        nodes_str = nodes_str + node
                    str = str + attack + '('+ times_str + ', attackers: ' + nodes_str + '), '
            f.close()
            result_file.write('{}: {}\n'.format(sim_number, str))
        result_file.write('\n')

result_file.close()
