import os
import datetime
import glob

class Args:
    sim_time = None
    time_window = None
    data_dir = None
    simulation_tool = None
    output_dir = None
    feat_folder = None

    def __init__(self):
        self.sim_time = "32400"
        self.time_window = "600"
        self.data_dir = "dataset/Dataset_Random"
        self.simulation_tool = "Cooja"
        self.output_dir = "output/{}s{}w{}"
        self.feat_folder = 'log/features_extracted/'

attack_names = {
    'Blackhole': 'BLACKHOLE/SEL FORWARD',
    'Selective_Forward': 'BLACKHOLE/SEL FORWARD',
    'Clone-ID': 'CLONE-ID or SYBIL',
    'Clone_Id': 'CLONE-ID or SYBIL',
    'Sybil': 'CLONE-ID or SYBIL',
    'DIS': 'DIS',
    'Hello_Flood': 'HELLO FLOOD',
    'Sinkhole': 'RANKS',
    'Ranks': 'RANKS',
    'Continuous_Sinkhole': 'RANKS',
    'Local_Repair': 'RANKS',
    'Version': 'VERSION',
    'Worst_Parent': 'WORST PARENT'
}

expected_attack_dict = {'BLACKHOLE/SEL FORWARD': [], 'CLONE-ID or SYBIL': [], 'DIS': [],
                        'HELLO FLOOD': [], 'RANKS': [],
                        'VERSION': [], 'WORMHOLE': [], 'WORST PARENT': []}


def fill_expected_attacks_dict(scenario_paths, args):
    info_paths = []
    for scenario_path in scenario_paths:
        info_paths.append(glob.glob(os.path.join(scenario_path, "Packet_Trace_{}s".format(args.sim_time), '*.txt')))

    for info_path in info_paths:
        with open(info_path[0], 'r') as f:
            lines = f.readlines()

            for line in lines:
                if 'Scenario' in line:
                    attack_name = line.split('Scenario')[-1].rstrip().lstrip()
                else:
                    sim_nr = line.split('-')[0].rstrip().lstrip()
                    attacker = line.split('-')[1].split('attacker: ')[1].split('at')[0].rstrip().lstrip()
                    attack_time = line.split('time: ')[-1].rstrip().lstrip()
            if attack_name != 'Legit':
                expected_attack_dict[attack_names[attack_name]].append({'sim_nr': sim_nr, 'attacker': attacker, 'time': attack_time})


def parse_attack_line(line, last_line, last_time):
    attack_messy, attacker_node = line.split('ATTACK ->')
    attack = attack_messy.lstrip().rstrip()
    attacker_nodes = []
    # Make sure attack name works for attack_dict etc
    if 'RANK' in attack:
        attack = 'RANKS'
    # Make sure attacker nodes are returned as list of strings
    nodes = attacker_node.split('[')[-1].split(']')[0].rstrip().lstrip()  # fe '7' or '8','3','2'
    if ',' in nodes:
        nodes = nodes.split(',')
    else:
        single_node = nodes
        nodes = []
        nodes.append(single_node)
    if 'ATTACK' in last_line:
        time = last_time
    else:
        time = last_line.split('time')[-1].split('.0. Devices')[0].rstrip().lstrip()
    if len(nodes) == 1:
        clean_node = nodes[0].strip('\"')
        attacker_node = clean_node
    else:
        for node in nodes:
            clean_node = node.split('\'')[1]
            if clean_node not in attacker_nodes:
                attacker_node = clean_node

    return attack, last_line, last_time, time, attacker_node


def process_file(file, result_file):
    correctly_classified_sims = 0
    correctly_identified_attackers = 0
    f = open(file, 'r')
    lines = f.readlines()

    # Get last part of path
    filename = file.split('/')[-1]
    # Remove filetype
    sim_number = filename.split('.')[0]
    attack_dict = {'BLACKHOLE/SEL FORWARD': [[], []], 'CLONE-ID or SYBIL': [[], []], 'DIS': [[], []],
                   'HELLO FLOOD': [[], []], 'RANKS': [[], []],
                   'VERSION': [[], []], 'WORMHOLE': [[], []], 'WORST PARENT': [[], []]}
    first_correct_attack = False
    # Get information from lines with "ATTACK"
    for line in lines:
        if 'ATTACK' in line:
            attack, last_line, last_time, attack_time, attacker_node = parse_attack_line(line, last_line, last_time)
            attack_dict[attack][0].append(attack_time)
            attack_dict[attack][1].append(attacker_node)

            for sim in expected_attack_dict[attack]:
                if sim['sim_nr'] == sim_number:
                    expected_attacker = sim['attacker']
                    expected_attack_time = sim['time']

                if int(attack_time) > int(expected_attack_time) / 1000000 and not first_correct_attack:
                    first_correct_attack = True
                    correctly_classified_sims += 1
                    if expected_attacker in attacker_node:
                        correctly_identified_attackers += 1
        else:
            last_time = 0
            last_line = line
    str = ""
    #
    for attack in attack_dict:
        if len(attack_dict[attack][0]) > 0:
            times_str = ""
            for el in attack_dict[attack][0]:
                if el != attack_dict[attack][0][0]:
                    times_str = times_str + ', '
                if attack_time != 0:
                    times_str = times_str + el
            attackers = []
            for node in attack_dict[attack][1]:
                if node not in attackers:
                    attackers.append(node)
            nodes_str = [attacker + ', ' for attacker in attackers][0]
            str = str + attack + '(' + times_str + ', attackers: ' + nodes_str + '), '
    f.close()
    result_file.write('{}: {}\n'.format(sim_number, str))
    return correctly_classified_sims, correctly_identified_attackers


def main(args = Args()):
    # Get all scenarios present in the chosen data directory
    scenario_paths = glob.glob(os.path.join(os.getcwd(), '..', args.data_dir, '*'))
    scenarios = []
    for path in scenario_paths:
        scenario = path.split('/')[-1]
        scenarios.append(scenario)

    output_filename = os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today()))
    result_file = open(output_filename, 'w')

    # Gather the expected result from dataset-folder
    fill_expected_attacks_dict(scenario_paths, args)

    # For each scenario, process output file for each simulation
    for scenario in scenarios:
        if os.path.exists(os.path.join(os.getcwd(), 'log', args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()), scenario)):
            filenames = glob.glob(os.path.join(os.getcwd(), 'log', args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()), scenario, '*'))
            result_file.write('{}\n'.format(scenario))
            # Variables for printing statistics for each scenario
            total_sims = len(filenames)
            # Parse each output file
            for file in filenames:
                correctly_classified_sims, correctly_identified_attackers = process_file(file, result_file)
            result_file.write('Results: {}/{} correctly classified, {}/{} identified attacker\n'.format(correctly_classified_sims,total_sims, correctly_identified_attackers, total_sims))
            result_file.write('\n')

    result_file.close()

if __name__ == '__main__':
    main()