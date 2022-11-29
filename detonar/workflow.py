import datetime
import glob
import os
import sys
import traceback
import subprocess
from subprocess import PIPE, STDOUT, CalledProcessError
import summarize_output_files
from detonar import parse_statistics


class Args:
    simulation_time = None
    time_window = None
    time_start = None
    data_dir = None
    simulation_tool = None
    output_dir = None
    feat_folder = None
    print_each_simulation = None
    chosen_simulation = None
    scenario = None
    time_feat_seconds = None
    time_feat_micro = None
    max_nr_neighbors = None
    def __init__(self):
        self.simulation_time = 27000
        self.time_window = 600
        self.time_start = 600
        self.data_dir = 'dataset/Dataset_Random_Stats_35'
        self.simulation_tool = 'Cooja'
        self.output_dir = 'output/{}s{}w{}'
        self.feat_folder = 'extended_features/'
        self.print_each_simulation = False
        self.time_feat_micro = 'TIME'
        self.time_feat_seconds = 'TIME'
        self.max_nr_neighbors = 15

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

def _get_simulations(scenario, args):
    sims_all = glob.glob(os.path.join(os.getcwd(), '..', args.data_dir, scenario,
                                  'Packet_Trace_' + str(args.simulation_time) + 's', '*.csv'))
    sims = [sim for sim in sims_all if 'stats' in sim]
    simulations = []
    if len(sims) > 0:
        for sim in sims:
            clean_sim = sim.split('/')[-1]
            sim_number = clean_sim.split('_')[0]
            simulations.append(sim_number)
    return simulations

def _get_simulations_csv(scenario, args):
    sims_all = glob.glob(os.path.join(os.getcwd(), '..', args.data_dir, scenario,
                                  'Packet_Trace_' + str(args.simulation_time) + 's', '*.csv'))
    sims = [sim for sim in sims_all if scenario in sim]
    simulations = []
    if len(sims) > 0:
        for sim in sims:
            clean_sim = sim.split('/')[-1]
            sim_number = clean_sim.split('.')[0].split('_')[0]
            simulations.append(sim_number)

    return list(set(simulations))

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

    # Parse statistics (instead of feature extraction)
    for scenario in scenarios:
        print("Parse statistics for scenario:", scenario, "\n")
        simulations = _get_simulations_csv(scenario, args)
        for sim in simulations:
            args.chosen_simulation = sim
            args.scenario = scenario
            parse_statistics.main(args)

    print("Running IDS\n")
    print("Result for each scenario and simulation is saved in: ", os.path.join(os.getcwd(), 'log',
                        args.output_dir.format(str(args.simulation_time), args.time_window, datetime.date.today())), "\n\n")

    # For each scenario, create a list of simulations existing for that scenario
    for scenario in scenarios:
        # Getting files depending on data directory, scenario and simulation time chosen
        simulations = _get_simulations(scenario, args)

        # Run IDS for each simulation in scenario
        '''              
        Running f.e:                
        python new_arima_ids.py --scenario="Legit" --chosen_simulation="101" --simulation_time=1500 --time_window=10 --time_start=10" 
                  "--lag_val=30 --data_dir="dataset/test_dataset" --simulation_tool="Cooja" --output_dir="output/1500s10w20221018" --feat_folders="log/features_extracted/"
        '''
        for sim in simulations:
            cmd = ids_cmd.format(scenario, sim, str(args.simulation_time), args.time_window, args.data_dir, args.simulation_tool,
                                 args.output_dir.format(str(args.simulation_time), args.time_window, datetime.date.today()), args.feat_folder,
                                 args.time_window)
            print(cmd)
            _run_command(cmd)

    print("Summarized results of all scenarios and simulation is saved in: ", os.path.join(os.getcwd(), 'log', 'results_summarized{}.txt'.format(datetime.date.today())))

    summarize_output_files.main(args)


if __name__ == '__main__':
    main()