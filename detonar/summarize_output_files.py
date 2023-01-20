"""
Summarizes all result files of DETONAR given the location of the result files,
the location of the dataset, the simulation time and the tim window size
"""
import datetime
import glob
import os

import settings_parser

attack_names = {
    "Blackhole": "BLACKHOLE/SEL FORWARD",
    "Selective_Forward": "BLACKHOLE/SEL FORWARD",
    "Clone-ID": "CLONE-ID or SYBIL",
    "Clone_ID": "CLONE-ID or SYBIL",
    "Clone_Id": "CLONE-ID or SYBIL",
    "Sybil": "CLONE-ID or SYBIL",
    "DIS": "DIS",
    "Hello_Flood": "HELLO FLOOD",
    "Sinkhole": "RANKS",
    "Ranks": "RANKS",
    "Continuous_Sinkhole": "RANKS",
    "Local_Repair": "RANKS",
    "Version": "VERSION",
    "Worst_Parent": "WORST PARENT",
}


def _get_expected_attacks_lines(info_file_path):
    with open(info_file_path[0], "r", encoding="utf8") as info_file:
        expected_lines = [
            line for line in info_file.readlines() if "Scenario" not in line
        ]
    return expected_lines


def _parse_attack_line(line, last_line, last_time):
    attack_messy, attacker_node = line.split("ATTACK ->")
    attack = attack_messy.lstrip().rstrip()
    attacker_nodes = []
    # Make sure attack name works for attack_dict etc
    if "RANK" in attack:
        attack = "RANKS"
    # Make sure attacker nodes are returned as list of strings
    nodes = attacker_node.split("[")[-1].split("]")[0].strip('"').rstrip().lstrip()
    if "," in nodes:
        nodes = nodes.split(",")
    else:
        single_node = nodes
        nodes = []
        nodes.append(single_node)
    if "ATTACK" in last_line:
        time = last_time
    else:
        time = last_line.split("time")[-1].split(". Devices")[0].rstrip().lstrip()
    if len(nodes) == 1:
        if "ATTACKER NODE: " in nodes[0]:
            nodes[0] = nodes[0].split("ATTACKER NODE: ")[1]
        clean_node = nodes[0].strip('"').strip("'")
        attacker_nodes.append(clean_node)
    else:
        for node in nodes:
            clean_node = node.strip('"').rstrip().lstrip().strip("'")
            attacker_nodes.append(clean_node)
    return attack, last_line, last_time, time, attacker_nodes


def _print_simulation(attack_dict):
    print_str = ""
    for attack in attack_dict:
        if len(attack_dict[attack][0]) > 0:
            times_str = ""
            for time in attack_dict[attack][0]:
                if time != attack_dict[attack][0][0]:
                    times_str = times_str + ", "
                if time != 0:
                    times_str = times_str + time
            attackers = []
            for node in attack_dict[attack][1]:
                if node not in attackers:
                    attackers.append(node)
            nodes_str = ""
            nodes_list = [attacker.strip("'") for attacker in attackers]
            for node in nodes_list:
                nodes_str = nodes_str + node + ", "
            print_str = (
                print_str
                + attack
                + "("
                + times_str
                + ", attackers: "
                + nodes_str
                + "), "
            )
    return print_str


def _process_file(sim_file, full_results_file, expected_attacks_lines, scenario, args):
    correctly_classified_sims = 0
    correctly_identified_attackers = 0
    alarm_raised = False
    early_alarm_raised = False
    with open(sim_file, "r", encoding="utf8") as result_file:
        lines = result_file.readlines()
        # Get last part of path
        filename = sim_file.split("/")[-1]
        # Remove filetype
        sim_number = filename.split(".")[0]
        if scenario != "Legit":
            expected_result_line = [
                line for line in expected_attacks_lines if sim_number in line
            ]
            expected_attacker = (
                expected_result_line[0]
                .split("-")[-1]
                .split("attacker: ")[-1]
                .split("at")[0]
                .rstrip()
                .lstrip()
            )
            expected_attack_time = (
                expected_result_line[0].split("time: ")[-1].rstrip().lstrip()
            )
        else:
            expected_attack_time = args.simulation_time * 1000000
        attack_dict = {
            "BLACKHOLE/SEL FORWARD": [[], []],
            "CLONE-ID or SYBIL": [[], []],
            "DIS": [[], []],
            "HELLO FLOOD": [[], []],
            "RANKS": [[], []],
            "VERSION": [[], []],
            "WORMHOLE": [[], []],
            "WORST PARENT": [[], []],
        }
        first_correct_attack = False
        # Get information from lines with "ATTACK"
        for line in lines:
            if "ATTACK" in line:
                (
                    attack,
                    last_line,
                    last_time,
                    attack_time,
                    attacker_nodes,
                ) = _parse_attack_line(line, last_line, last_time)
                attacker_nodes = [node.split("-")[-1] for node in attacker_nodes]
                attack_dict[attack][0].append(attack_time)
                for attacker_node in attacker_nodes:
                    attack_dict[attack][1].append(attacker_node)
                if scenario != "Legit":
                    if (
                        expected_attacker in attacker_nodes
                    ) and correctly_identified_attackers == 0:
                        correctly_identified_attackers += 1
                    if (
                        int(attack_time) > int(expected_attack_time) / 1000000
                        and (attack == attack_names[scenario])
                        and not first_correct_attack
                    ):
                        first_correct_attack = True
                        correctly_classified_sims += 1
                    if int(attack_time) > int(expected_attack_time) / 1000000:
                        alarm_raised = True
                if int(attack_time) < int(expected_attack_time) / 1000000:
                    early_alarm_raised = True

            else:
                last_time = 0
                last_line = line
            print_str = _print_simulation(attack_dict)
        full_results_file.write(f"{sim_number}: {print_str}\n")
    return (
        correctly_classified_sims,
        correctly_identified_attackers,
        alarm_raised,
        early_alarm_raised,
    )


def main():
    """
    Parses and summarizes output files from DETONAR
    :param args: Should be passed from workflow
    """
    args = settings_parser.arg_parse()
    # Get all scenarios present in the chosen data directory
    scenario_paths = glob.glob(os.path.join(os.getcwd(), "..", args.data_dir, "*"))
    scenarios = []
    for path in scenario_paths:
        scenario = path.split("/")[-1]
        scenarios.append(scenario)

    result_summary_filename = os.path.join(
        os.getcwd(), "log", f"results_summarized{datetime.date.today()}.txt"
    )

    full_results_filename = os.path.join(
        os.getcwd(), "log", f"results_full{datetime.date.today()}.txt"
    )

    with open(result_summary_filename, "w", encoding="utf8") as summary_file, open(
        full_results_filename, "w", encoding="utf8"
    ) as full_results_file:

        # Gather the expected result from dataset-folder
        info_paths = []
        for scenario_path in scenario_paths:
            info_paths.append(
                glob.glob(
                    os.path.join(
                        scenario_path,
                        f"Packet_Trace_{args.simulation_time}s",
                        "*.txt",
                    )
                )[0]
            )

        # For each scenario, process output file for each simulation
        for scenario in scenarios:
            info_file_path = [path for path in info_paths if scenario in path]
            expected_attack_lines = _get_expected_attacks_lines(info_file_path)

            if os.path.exists(
                os.path.join(
                    os.getcwd(),
                    "log",
                    args.output_dir,
                    scenario,
                )
            ):
                filenames = glob.glob(
                    os.path.join(
                        os.getcwd(),
                        "log",
                        args.output_dir,
                        scenario,
                        str(args.simulation_time),
                        "*",
                    )
                )
                summary_file.write(f"{scenario}\n")
                full_results_file.write(f"{scenario}\n")
                # Variables for printing statistics for each scenario
                total_sims = len(filenames)
                # Parse each output file
                correctly_classified_sims_result = 0
                correctly_identified_attackers_result = 0
                alarms_raised = 0
                early_alarms_raised = 0
                for file in filenames:
                    (
                        correctly_classified_sims,
                        correctly_identified_attackers,
                        alarm_raised,
                        early_alarm_raised,
                    ) = _process_file(
                        file, full_results_file, expected_attack_lines, scenario, args
                    )
                    correctly_classified_sims_result += correctly_classified_sims
                    correctly_identified_attackers_result += (
                        correctly_identified_attackers
                    )
                    if alarm_raised:
                        alarms_raised += 1
                    if early_alarm_raised:
                        early_alarms_raised += 1
                summary_file.write(
                    f"Results: {correctly_classified_sims_result}/"
                    f"{total_sims} correctly classified, "
                    f"{correctly_identified_attackers_result}/"
                    f"{total_sims} identified attacker\n"
                )
                summary_file.write(
                    f"{alarms_raised}/{total_sims} alarms raised, "
                    f"{early_alarms_raised}/{total_sims} false positives before alarm \n"
                )
                summary_file.write("\n")
                full_results_file.write("\n")


if __name__ == "__main__":
    main()
