import datetime
import glob
import os
import sys
import traceback
import subprocess
from subprocess import PIPE, STDOUT, CalledProcessError


class Args:
    sim_time = None
    time_window = None
    data_dir = None
    simulation_tool = None
    output_dir = None
    feat_folder = None

    def __init__(self):
        self.sim_time = '32400'
        self.time_window = '600'
        self.data_dir = 'dataset/16_Nodes_Random'
        self.simulation_tool = 'Cooja'
        self.output_dir = 'output/{}s{}w{}'
        self.feat_folder = 'log/features_extracted/'

def _run_command(command):
    try:
        proc = subprocess.run(command, stdout=PIPE, stderr=STDOUT, shell=True, universal_newlines=True)
        return proc.returncode, proc.stdout if proc.stdout else ''
    except CalledProcessError as e:
        print(f"Command failed: {e}", file=sys.stderr)
        return e.returncode, e.stdout if e.stdout else ''
    except (OSError, Exception) as e:
        traceback.print_exc()
        return -1, str(e)


def summarize_output_files(scenarios, args):
    # Parse all output files and put it all in one result-file
    output_filename = os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today()))
    result_file = open(output_filename, 'w')

    result_file.write(
        "Summarized results for simulations of length {}s and {}s time window\n\n".format(args.sim_time,
                                                                                          args.time_window))

    for scenario in scenarios:
        # Example path: log/output/32400s600s2022-10-20/Rank, for Rank scenario
        if os.path.exists(
                os.path.join(os.getcwd(), 'log',
                             args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()),
                             scenario)):
            # Get all files for scenario
            filenames = glob.glob(
                os.path.join(os.getcwd(), 'log',
                             args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()),
                             scenario, '*'))

            result_file.write('{}\n'.format(scenario))

            # For each file, extract attacks and time of attacks
            for file in filenames:
                f = open(file, 'r')
                lines = f.readlines()

                filename = file.split('/')[-1]
                # Remove file extension
                sim_number = filename.split('.')[0]
                attack_dict = {'BLACKHOLE/SEL FORWARD': [], 'CLONE-ID or SYBIL': [], 'DIS': [], 'HELLO FLOOD': [],
                               'RANKS': [],
                               'VERSION': [], 'WORMHOLE': [], 'WORST PARENT': []}
                for line in lines:
                    if 'ATTACK' in line and 'ATTACK' not in last_line:
                        if 'ATTACKS' in line:
                            attack_messy, attacker_node = line.split('ATTACKS ->')
                        else:
                            attack_messy, attacker_node = line.split('ATTACK ->')
                        attack = attack_messy.lstrip().rstrip()
                        # Get the time when the anomaly was raised
                        time = last_line.split('time')[-1].split('.0. Devices')[0].rstrip().lstrip()
                        if attack == 'RANK':
                            attack = 'RANKS'
                        attack_dict[attack].append(time)
                    last_line = line
                str = ""
                for attack in attack_dict:
                    if len(attack_dict[attack]) > 0:
                        times_str = ""
                        for el in attack_dict[attack]:
                            if el != attack_dict[attack][0]:
                                times_str = times_str + ', '
                            times_str = times_str + el
                        str = str + attack + '(' + times_str + '), '
                f.close()
                result_file.write('{}: {}\n'.format(sim_number, str))
            result_file.write('\n')
    result_file.close()


def main():

    args = Args()

    feature_cmd = "python3 feature_extractor.py --scenario=\"{}\" --simulation_time={} --time_window={} --lag_val=30 " \
                  "--data_dir=\"{}\" --simulation_tool=\"{}\" --time_start={}"

    ids_cmd = "python3 new_arima_ids.py --scenario=\"{}\" --chosen_simulation=\"simulation-{}\" --simulation_time={} --time_window={} " \
              "--lag_val=30 --data_dir=\"{}\" --simulation_tool=\"{}\" --output_dir=\"{}\" --feat_folders=\"{}\" --time_start={}"

    # Get all scenarios present in the chosen data directory
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
    for scenario in scenarios:
        print("Extracting features for scenario:", scenario, "\n")
        cmd = feature_cmd.format(scenario, args.sim_time, args.time_window, args.data_dir, args.simulation_tool, args.time_window)
        _run_command(cmd)
        #os.system(feature_cmd.format(scenario, args.sim_time, args.time_window, args.data_dir, args.simulation_tool, args.time_window))

    print("Running IDS\n")
    print("Result for each scenario and simulation is saved in: ", os.path.join(os.getcwd(), 'log',
                        args.output_dir.format(args.sim_time, args.time_window, datetime.date.today())), "\n\n")

    # For each scenario, create a list of simulations existing for that scenario
    for scenario in scenarios:
        # Getting files depending on data directory, scenario and simulation time chosen
        sims = glob.glob(os.path.join(os.getcwd(), '..', args.data_dir, scenario,
                                      'Packet_Trace_' + args.sim_time + 's', '*.csv'))
        simulations = []
        if len(sims) > 0:
            for sim in sims:
                clean_sim = sim.split('/')[-1]
                sim_number = clean_sim.split('.')[0]
                simulations.append(sim_number)

        simulations.sort(key=int)

        # Run IDS for each simulation in scenario
        '''                  
        Running f.e:                
        python new_arima_ids.py --scenario="Legit" --chosen_simulation="101" --simulation_time=1500 --time_window=10 --time_start=10" 
                  "--lag_val=30 --data_dir="dataset/test_dataset" --simulation_tool="Cooja" --output_dir="output/1500s10w20221018" --feat_folders="log/features_extracted/"
        '''
        for sim in simulations:
            cmd = ids_cmd.format(scenario, sim, args.sim_time, args.time_window, args.data_dir, args.simulation_tool,
                                 args.output_dir.format(args.sim_time, args.time_window, datetime.date.today()), args.feat_folder,
                                 args.time_window)
            print(cmd)
            _run_command(cmd)

    print("Summarized results of all scenarios and simulation is saved in: ", os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today())))
    summarize_output_files(scenarios, args)


if __name__ == '__main__':
    main()