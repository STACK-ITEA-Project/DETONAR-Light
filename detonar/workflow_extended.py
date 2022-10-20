import datetime
import glob
import subprocess
import os
import parse_statistics

class args:
    simulation_time = 3600
    time_window = 60
    time_start = 60
    data_dir = "dataset/16_Nodes_Cooja"
    simulation_tool = "Cooja"
    output_dir = "output/{}s{}w{}"
    time_feat_micro = "PHY_LAYER_ARRIVAL_TIME(US)"
    feat_folder= 'log/features_extracted/'
    scenario = ""
    chosen_simulation = ""
    extended_feat_folder = "extended_features/"

extended = True

feature_cmd = "python feature_extractor.py --scenario=\"{}\" --simulation_time={} --time_window={} --lag_val=30 " \
              "--data_dir=\"{}\" --simulation_tool=\"{}\" --time_start={}"

ids_cmd = "python new_arima_ids.py --scenario=\"{}\" --chosen_simulation=\"simulation-{}\" --simulation_time={} --time_window={} " \
          "--lag_val=30 --data_dir=\"{}\" --simulation_tool=\"{}\" --output_dir=\"{}\" --feat_folders=\"{}\" --time_start={}"

# Get all scenarios present in the chosen directory for data set
# Example scenarios: Legit, Sinkhole, Blackhole, Rank, Version etc
scenario_paths = glob.glob(os.path.join(os.getcwd(), '..', args.data_dir, '*'))
scenarios = []
for path in scenario_paths:
    scenario = path.split('/')[-1]
    scenarios.append(scenario)

# Perform feature extraction
'''
Running f.e:
python feature_extractor.py --scenario="Legit" --simulation_time=1500 --time_window=10 --lag_val=30 
              --data_dir="dataset/test_dataset" --simulation_tool="Cooja --time_start=10"
'''
'''
for scenario in scenarios:
    os.system(feature_cmd.format(scenario, args.simulation_time, args.time_window, args.data_dir, args.simulation_tool, args.time_window))

'''

# For each scenario, create a list of simulations existing for that scenario
simulations  = []
for scenario in scenarios:
    # Getting files depending on data directory, scenario and simulation time chosen
    sims = glob.glob(os.path.join(os.getcwd(), '..', args.data_dir, scenario,
                                   'Packet_Trace_' + str(args.simulation_time) + 's', '*.csv'))
    if len(sims) > 0:
        for sim in sims:
            clean_sim = sim.split('/')[-1]
            sim_number = clean_sim.split('.')[0]
            simulations.append(sim_number)

    simulations.sort(key=int)

    # Run IDS for each simulation in scenario
    '''                  
    Running f.e:                
    python new_arima_ids.py --scenario="Legit" --chosen_simulation="simulation-101" --simulation_time=1500 --time_window=10 --time_start=10" 
              "--lag_val=30 --data_dir="dataset/test_dataset" --simulation_tool="Cooja" --output_dir="output/1500s10w20221018" --feat_folders="log/features_extracted/"
    '''
    for sim in simulations:
        args.scenario = scenario
        args.chosen_simulation = sim

        # Before running IDS, parse statistics
        if extended:
            # Perform "parse statistics"
            parse_statistics.parse(args)
            # Copy feature files DAOs and DIOs to correct directory
            filenames = glob.glob(
                os.path.join(os.getcwd(), args.feat_folder, args.scenario, str(int(args.simulation_time)), '*'))
            filenames.sort()
            # all_files = get_files(filenames, args)
            all_files = [item for item in filenames if args.chosen_simulation in item]
            # Getting DAOs, to simulate gateways being sent DAOs
            dao_file = [item for item in all_files if 'DAOs' in item]
            # daos = read_csv(dao_file[0])
            # Pick file containing DIOs
            dio_file = [item for item in all_files if 'DIOs' in item]
            # dios = read_csv(dio_file[0])
            for dao in dao_file:
                os.system("cp {} {}".format(dao, 'extended_features/{}/{}/{}'.format(args.scenario, args.simulation_time, args.simulation)))

        # ids_result = subprocess.run(ids_cmd.format(scenario, sim, simulation_time, time_window, data_dir, simulation_tool))
        cmd = ids_cmd.format(scenario, sim, args.simulation_time, args.time_window, args.data_dir, args.simulation_tool, args.output_dir.format(args.simulation_time, args.time_window, datetime.date.today()), args.extended_feat_folder, args.time_window)
        print(cmd)
        os.system(cmd)


# Parse all output files and put it all in one result-file

output_filename = os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today()))
result_file = open(output_filename, 'w')

result_file.write("Summarized results for simulations of lenght {}s and {}s time window\n\n".format(args.simulation_time, args.time_window))

for scenario in scenarios:
    if os.path.exists(os.path.join(os.getcwd(), 'log', args.output_dir.format(args.simulation_time, args.time_window,datetime.date.today()), scenario)):
        filenames = glob.glob(os.path.join(os.getcwd(), 'log', args.output_dir.format(args.simulation_time, args.time_window,datetime.date.today()), scenario, '*'))

        result_file.write('{}\n'.format(scenario))
        for file in filenames:
            f = open(file, 'r')
            lines = f.readlines()

            # Get last part of path
            filename = file.split('/')[-1]
            # Remove file extension
            sim_number = filename.split('.')[0]
            attack_dict = {'BLACKHOLE/SEL FORWARD': [], 'CLONE-ID or SYBIL': [], 'DIS': [], 'HELLO FLOOD': [], 'RANKS': [],
             'VERSION': [], 'WORMHOLE': [], 'WORST PARENT': []}
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