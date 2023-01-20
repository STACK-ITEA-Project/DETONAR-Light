"""
Run the DETONAR pipeline.
"""
import datetime
import glob
import os
import subprocess
import sys
import traceback
from subprocess import PIPE, STDOUT, CalledProcessError

import summarize_output_files
import settings_parser

def _run_command(command):
    try:
        proc = subprocess.run(
            command,
            stdout=PIPE,
            stderr=STDOUT,
            shell=True,
            universal_newlines=True,
            check=True,
        )
        return proc.returncode, proc.stdout if proc.stdout else ""
    except CalledProcessError as inst:
        print(f"Command failed: {inst}", file=sys.stderr)
        return inst.returncode, inst.stdout if inst.stdout else ""
    except (OSError, subprocess.SubprocessError) as inst:
        traceback.print_exc()
        return -1, str(inst)


def _get_simulations(scenario, args):
    sims_all = glob.glob(
        os.path.join(
            os.getcwd(),
            "..",
            args.data_dir,
            scenario,
            "Packet_Trace_" + str(args.simulation_time) + "s",
            "*.csv",
        )
    )
    sims = [sim for sim in sims_all if "stats" in sim]
    simulations = []
    if len(sims) > 0:
        for sim in sims:
            clean_sim = sim.split("/")[-1]
            sim_number = clean_sim.split("_")[0]
            simulations.append(sim_number)
    return simulations


def _get_simulations_csv(scenario, args):
    sims_all = glob.glob(
        os.path.join(
            os.getcwd(),
            "..",
            args.data_dir,
            scenario,
            "Packet_Trace_" + str(args.simulation_time) + "s",
            "*.csv",
        )
    )
    sims = [sim for sim in sims_all if scenario in sim]
    simulations = []
    if len(sims) > 0:
        for sim in sims:
            clean_sim = sim.split("/")[-1]
            sim_number = clean_sim.split(".")[0].split("_")[0]
            simulations.append(sim_number)

    return list(set(simulations))


def main():
    """
    Run statistic parsing on a given dataset
    Run IDS on the parsed statistics files
    Create two files for the result:
        * a summary with statistics for all simulations
        * a file with the specific attacks and attacker for each simulation
    """
    args = settings_parser.arg_parse()

    # Get all scenarios present in the chosen data directory
    scenario_paths = glob.glob(os.path.join(os.getcwd(), "..", args.data_dir, "*"))
    scenarios = []
    for path in scenario_paths:
        scenario = path.split("/")[-1]
        scenarios.append(scenario)

    # Parse statistics (instead of feature extraction)
    for scenario in scenarios:
        print("Parse statistics for scenario:", scenario, "\n")
        simulations = _get_simulations_csv(scenario, args)
        for sim in simulations:
            cmd = (
                f'python3 parse_statistics.py --scenario="{scenario}" --chosen_simulation="{sim}" '
                f"--simulation_time={args.simulation_time} --feat_folders"
                f"=\"{args.feat_folders}\" --time_window={args.time_window} "
                f"--lag_val=30 --data_dir=\"{args.data_dir}\" "
                f"--time_start={args.time_window} --time_feat_micro"
                f"=\"{args.time_feat_micro}\" --max_nr_neighbors={args.max_nr_neighbors}"
            )
            _run_command(cmd)

    print("Running IDS\n")
    print(
        "Result for each scenario and simulation is saved in: ",
        os.path.join(
            os.getcwd(),
            "log",
            args.output_dir,
        ),
        "\n\n",
    )

    # For each scenario, create a list of simulations existing for that scenario
    for scenario in scenarios:
        # Getting files depending on data directory, scenario and simulation time chosen
        simulations = _get_simulations(scenario, args)

        # Run IDS for each simulation in scenario
        for sim in simulations:

            cmd = (
                f'python3 new_arima_ids.py --scenario="{scenario}" --chosen_simulation='
                f'"{sim}" --simulation_time={args.simulation_time} '
                f'--time_window={args.time_window} --lag_val=30 --data_dir="{args.data_dir}" '
                f'--output_dir="{args.output_dir}" '
                f'--feat_folders="{args.feat_folders}" --time_start={args.time_window}'
            )
            print(cmd)
            _run_command(cmd)


    cmd = f'python3 summarize_output_files.py --data_dir="{args.data_dir}" ' \
          f'--simulation_time={args.simulation_time} --time_window={args.time_window} ' \
          f'--output_dir="{args.output_dir}"'
    print(cmd)
    _run_command(cmd)

    print(
        "Summarized results of all scenarios and simulation is saved in: ",
        os.path.join(
            os.getcwd(), "log", f"results_summarized{datetime.date.today()}.txt"
        ),
    )


if __name__ == "__main__":
    main()
