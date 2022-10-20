import datetime
import glob
import subprocess
import os
'''
scenarios = ['Blackhole', 'Clone_ID', 'Continuous_Sinkhole', 'DIS', 'Delayed_Reply',
             'Hello_Flood', 'Legitimate', 'Local_Repair', 'Rank', 'Replay', 'Selective_Forward', 'Sinkhole', 'Sybil',
             'Version', 'Wormhole', 'Worst_Parent']'''
#scenarios = ['Legit', 'Sinkhole']
sim_time = "3600"
time_window = "60"
#data_dir = "dataset/16_Nodes_Dataset"
data_dir = "dataset/16_Nodes_Cooja"
simulation_tool = "Cooja"
output_dir = "output/{}s{}w{}"
feat_folder= 'log/features_extracted/'

feature_cmd = "python feature_extractor.py --scenario=\"{}\" --simulation_time={} --time_window={} --lag_val=30 " \
              "--data_dir=\"{}\" --simulation_tool=\"{}\" --time_start={}"

ids_cmd = "python new_arima_ids.py --scenario=\"{}\" --chosen_simulation=\"simulation-{}\" --simulation_time={} --time_window={} " \
          "--lag_val=30 --data_dir=\"{}\" --simulation_tool=\"{}\" --output_dir=\"{}\" --feat_folders=\"{}\" --time_start={}"

scenario_paths = glob.glob(os.path.join(os.getcwd(), '..', data_dir, '*'))
scenarios = []
for path in scenario_paths:
    scenario = path.split('/')[-1]
    scenarios.append(scenario)
'''
Running f.e:
python feature_extractor.py --scenario="Legit" --simulation_time=1500 --time_window=10 --lag_val=30 
              --data_dir="dataset/test_dataset" --simulation_tool="Cooja --time_start=10"
'''

simulations  = []

for scenario in scenarios:
    os.system(feature_cmd.format(scenario, sim_time, time_window, data_dir, simulation_tool, time_window))

for scenario in scenarios:
    # Getting files depending on data directory, scenario and simulation time chosen
    sims = glob.glob(os.path.join(os.getcwd(), '..', data_dir, scenario,
                                   'Packet_Trace_' + sim_time + 's', '*.csv'))
    if len(sims) > 0:
        for sim in sims:
            clean_sim = sim.split('/')[-1]
            simulations.append(sim)

    '''                  
    Running f.e:                
    python new_arima_ids.py --scenario="Legit" --chosen_simulation="101" --simulation_time=1500 --time_window=10 --time_start=10" 
              "--lag_val=30 --data_dir="dataset/test_dataset" --simulation_tool="Cooja" --output_dir="output/1500s10w20221018" --feat_folders="log/features_extracted/"
    '''
    for sim in simulations:
        # Get last part of path
        filename = sim.split('/')[-1]
        # Remove filetype
        sim_number = filename.split('.')[0]
        # ids_result = subprocess.run(ids_cmd.format(scenario, sim, sim_time, time_window, data_dir, simulation_tool))
        cmd = ids_cmd.format(scenario, sim_number, sim_time, time_window, data_dir, simulation_tool, output_dir.format(sim_time, time_window, datetime.date.today()), feat_folder, time_window)
        print(cmd)
        os.system(cmd)

# "Parse" output files at put it all in one result-file

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
            for line in lines:
                if 'ATTACK' in line and 'ATTACK' not in last_line:
                    attack_messy, attacker_node = line.split('ATTACK ->')
                    attack = attack_messy.lstrip().rstrip()
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



