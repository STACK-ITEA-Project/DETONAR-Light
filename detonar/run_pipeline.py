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


def main():
    """
    Run feature extraction on a given dataset
    Run IDS on the extracted features
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

    # Perform feature extraction
    for scenario in scenarios:
        print("Extracting features for scenario:", scenario, "\n")
        cmd = (
            f'python3 feature_extractor.py --scenario="{scenario}" '
            f"--simulation_time={args.simulation_time} --time_window={args.time_window} "
            f"--lag_val=30 --data_dir=\"{args.data_dir}\" --time_start={args.time_window}"
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
        sims = glob.glob(
            os.path.join(
                os.getcwd(),
                "..",
                args.data_dir,
                scenario,
                "Packet_Trace_" + str(args.simulation_time) + "s",
                "*.csv",
            )
        )
        simulations = []
        if len(sims) > 0:
            for sim in sims:
                clean_sim = sim.split("/")[-1]
                sim_number = clean_sim.split(".")[0]
                simulations.append(sim_number)

        simulations.sort(key=int)

        # Run IDS for each simulation in scenario
        for sim in simulations:
            cmd = (
                f'python3 new_arima_ids.py --scenario="{scenario}" '
                f"--chosen_simulation=\"simulation-{sim}\" --simulation_time={args.simulation_time}"
                f" --time_window={args.time_window} --lag_val=30 "
                f"--data_dir=\"{args.data_dir}\" --output_dir=\"{args.output_dir}\""
                f" --feat_folders=\"{args.feat_folders}\" --time_start={args.time_window}"
            )

            print(cmd)
            _run_command(cmd)

    cmd = f'python3 summarize_output_files.py --data_dir="{args.data_dir}" ' \
        f'--simulation_time={args.simulation_time} --time_window={args.time_window} ' \
        f'--output_dir=\"{args.output_dir}\"'

    print(cmd)
    # Summarize the results of all scenarios run
    _run_command(cmd)

    print(
        "Summarized results of all scenarios and simulation is saved in: ",
        os.path.join(
            os.getcwd(), "log", f"results_summarized{datetime.date.today()}.txt"
        ),
    )


if __name__ == "__main__":
    main()
