import os
import datetime
import glob
import math

class Args:
    sim_time = None
    time_window = None
    data_dir = None
    simulation_tool = None
    output_dir = None
    feat_folder = None
    print_each_simulation = None

    def __init__(self):
        self.sim_time = "32400"
        self.time_window = "600"
        self.data_dir = "dataset/Dataset_Random"
        self.simulation_tool = "Cooja"
        #self.output_dir = "output/{}s{}w{}_noAck"
        self.output_dir = "output/{}s{}w{}"
        self.feat_folder = 'log/features_extracted/'
        self.print_each_simulation = False

attack_names = {
    'Blackhole': 'BLACKHOLE/SEL FORWARD',
    'Selective_Forward': 'BLACKHOLE/SEL FORWARD',
    'Clone-ID': 'CLONE-ID or SYBIL',
    'Clone_ID': 'CLONE-ID or SYBIL',
    'Clone_Id': 'CLONE-ID or SYBIL',
    'Sybil': 'CLONE-ID or SYBIL',
    'DIS': 'DIS',
    'Hello_Flood': 'HELLO FLOOD',
    'Sinkhole': 'RANKS',
    'Ranks': 'RANKS',
    'Rank': 'RANKS',
    'Continuous_Sinkhole': 'RANKS',
    'Local_Repair': 'RANKS',
    'Version': 'VERSION',
    'Worst_Parent': 'WORST PARENT'
}

def get_key(dict, val):
    for key, value in dict.items():
        if val == value:
            return key

    return "key doesn't exist"
def get_expected_attacks_lines(info_file_path, args):
    expected_lines = []
    with open(info_file_path[0], 'r') as f:
        lines = f.readlines()

        for line in lines:
            if 'Scenario' in line:
                attack_name = line.split('Scenario')[-1].rstrip().lstrip()

            else:
                expected_lines.append(line)
    return expected_lines


def parse_attack_line(line, last_line, last_time):
    attack_messy, attacker_node = line.split('ATTACK ->')
    attack = attack_messy.lstrip().rstrip()
    attacker_nodes = []
    # Make sure attack name works for attack_dict etc
    if 'RANK' in attack:
        attack = 'RANKS'
    # Make sure attacker nodes are returned as list of strings
    nodes = attacker_node.split('[')[-1].split(']')[0].strip('\"').rstrip().lstrip()  # fe '7' or '8','3','2'
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
        if 'ATTACKER NODE: ' in nodes[0]:
            nodes[0] = nodes[0].split('ATTACKER NODE: ')[1]
        clean_node = nodes[0].strip('\"').strip('\'')
        attacker_nodes.append(clean_node)
    else:
        for node in nodes:
            clean_node = node.strip('\"').rstrip().lstrip().strip('\'')
            attacker_nodes.append(clean_node)
    return attack, last_line, last_time, time, attacker_nodes


def process_file(scenario_file, result_file, expected_attacks_lines, scenario, args):
    correctly_classified_sims = 0
    correctly_identified_attackers = 0
    alarm_raised = False
    early_alarm_raised = False
    f = open(scenario_file, 'r')
    lines = f.readlines()

    # Get last part of path
    filename = scenario_file.split('/')[-1]
    # Remove filetype
    sim_number = filename.split('.')[0]
    if scenario != 'Legit':
        # Example of expected result line: "00005 - attacker:  13 at time: 26114451856"
        expected_result_line = [line for line in expected_attacks_lines if sim_number in line]
        expected_attacker = expected_result_line[0].split('-')[-1].split('attacker: ')[-1].split('at')[0].rstrip().lstrip()
        expected_attack_time = expected_result_line[0].split('time: ')[-1].rstrip().lstrip()
    else:
        expected_attack_time = 32400*1000000
    attack_dict = {'BLACKHOLE/SEL FORWARD': [[], []], 'CLONE-ID or SYBIL': [[], []], 'DIS': [[], []],
                   'HELLO FLOOD': [[], []], 'RANKS': [[], []],
                   'VERSION': [[], []], 'WORMHOLE': [[], []], 'WORST PARENT': [[], []]}
    first_correct_attack = False
    # Get information from lines with "ATTACK"
    for line in lines:
        if 'ATTACK' in line:
            attack, last_line, last_time, attack_time, attacker_nodes = parse_attack_line(line, last_line, last_time)
            attack_dict[attack][0].append(attack_time)
            [attack_dict[attack][1].append(attacker_node) for attacker_node in attacker_nodes]
            if scenario != 'Legit':
                if (expected_attacker in attacker_nodes) and correctly_identified_attackers == 0:
                    correctly_identified_attackers += 1
                if int(attack_time) > int(expected_attack_time) / 1000000 and (attack == attack_names[scenario]) and not first_correct_attack:
                    first_correct_attack = True
                    correctly_classified_sims += 1
                if int(attack_time) > int(expected_attack_time) / 1000000:
                    alarm_raised = True
            if int(attack_time) < int(expected_attack_time) / 1000000:
                early_alarm_raised = True
             
        else:
            last_time = 0
            last_line = line
    if args.print_each_simulation:
        print_str = ""
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
                nodes_str = ""
                nodes_list = [attacker.strip("\'") for attacker in attackers]
                for node in nodes_list:
                    nodes_str = nodes_str + node + ', '
                print_str = print_str + attack + '(' + times_str + ', attackers: ' + nodes_str + '), '
        f.close()
        result_file.write('{}: {}\n'.format(sim_number, print_str))
    return correctly_classified_sims, correctly_identified_attackers, alarm_raised, early_alarm_raised


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

    info_paths = []
    for scenario_path in scenario_paths:
        info_paths.append(glob.glob(os.path.join(scenario_path, "Packet_Trace_{}s".format(args.sim_time), '*.txt'))[0])

    # For each scenario, process output file for each simulation
    for scenario in scenarios:
        info_file_path = [path for path in info_paths if scenario in path]
        expected_attacks_lines = get_expected_attacks_lines(info_file_path, args)

        if os.path.exists(os.path.join(os.getcwd(), 'log', args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()), scenario)):
            filenames = glob.glob(os.path.join(os.getcwd(), 'log', args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()), scenario, '*'))
            result_file.write('{}\n'.format(scenario))
            # Variables for printing statistics for each scenario
            total_sims = len(filenames)
            # Parse each output file
            correctly_classified_sims_result = 0
            correctly_identified_attackers_result = 0
            alarms_raised = 0
            early_alarms_raised = 0
            for file in filenames:
                correctly_classified_sims, correctly_identified_attackers, alarm_raised, early_alarm_raised = process_file(file, result_file, expected_attacks_lines, scenario, args)
                correctly_classified_sims_result += correctly_classified_sims
                correctly_identified_attackers_result += correctly_identified_attackers
                if alarm_raised:
                    alarms_raised += 1
                if early_alarm_raised:
                    early_alarms_raised += 1
            result_file.write('Results: {}/{} correctly classified, {}/{} identified attacker\n'.format(correctly_classified_sims_result,total_sims, correctly_identified_attackers_result, total_sims))
            result_file.write('{}/{} alarms raised, {}/{} false positives before alarm \n'.format(alarms_raised, total_sims, early_alarms_raised, total_sims))
            result_file.write('\n')

    result_file.close()

if __name__ == '__main__':
    main()
