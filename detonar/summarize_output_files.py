import os
import datetime
import glob

scenarios = ['Legit', 'Blackhole']
sim_time = "1500"
time_window = "10"
#data_dir = "dataset/16_Nodes_Dataset"
data_dir = "dataset/test_dataset"
simulation_tool = "Cooja"
output_dir = "output/{}s{}w{}"
feat_folder = 'log/features_extracted/'


output_filename = os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today()))
result_file = open(output_filename, 'w')

for scenario in scenarios:
    if os.path.exists(os.path.join(os.getcwd(), 'log', output_dir.format(sim_time, time_window,datetime.date.today()), scenario)):
        filenames = glob.glob(os.path.join(os.getcwd(), 'log', output_dir.format(sim_time, time_window,datetime.date.today()), scenario, '*'))

        result_file.write('{}\n'.format(scenario))
        for file in filenames:
            f = open(file, 'r')
            lines = f.readlines()

            # Get last part of path
            filename = file.split('/')[-1]
            # Remove filetype
            sim_number = filename.split('.')[0]
            attack_dict = {'BLACKHOLE/SEL FORWARD': [], 'CLONE-ID or SYBIL': [], 'DIS': [], 'HELLO FLOOD': [], 'RANKS': [],
             'VERSION': [], 'WORMHOLE': [], 'WORST PARENT': []}
            times_list = []
            #nodes_ist = []
            for line in lines:
                if 'ATTACK' in line and 'ATTACK' not in last_line:
                    attack_messy, attacker_node = line.split('ATTACK ->')
                    attack = attack_messy.lstrip().rstrip()
                    #node = attacker_node.split('[')[-1].split(']')[0]
                    first, second = last_line.split('time')
                    time = last_line.split('time')[-1].split('.0. Devices')[0].rstrip().lstrip()
                    attack_dict[attack].append(time)
                last_line = line
            str = ""
            for attack in attack_dict:
                if len(attack_dict[attack]) > 0:
                    times_str = ""
                    for el in attack_dict[attack]:
                        if el != attack_dict[attack][0]:
                            times_str = times_str +', '
                        times_str = times_str + el
                    str = str + attack + '('+ times_str +'), '
            f.close()
            result_file.write('{}: {}\n'.format(sim_number, str))
        result_file.write('\n')

result_file.close()
