import glob
import os
import random
import time as tm
import warnings

import numpy as np
import pandas as pd
import pmdarima as pm
from joblib import Parallel, delayed

warnings.filterwarnings("ignore")

import settings_parser
from reconstruct_dodag import extract_dodag_before_after
from attack_class import extract_neighborhood, classify_attack_from_dodag


# Read csv file not using first column as index
def _read_csv(path_to_file):
    data = pd.read_csv(path_to_file, index_col=False)
    return data


# Get list of csv files and select those for train and those for test
def _get_files(filenames):
    all_files = []
    for filename in filenames:
        files = glob.glob(os.path.join(filename, "*.csv"))
        all_files.append(files)
    # From list of list create a single list with all files' names
    all_files_list = [item for sublist in all_files for item in sublist]
    random.shuffle(all_files_list)

    return all_files_list


def _get_series(file, feature):
    data = pd.read_csv(file)
    return data[feature]


def _get_row_list(file, index):
    data = pd.read_csv(file)
    return data.iloc[index]


def _get_node_name_from_id(node_id):
    if node_id == 1:
        return "SINKNODE-1"
    return f"SENSOR-{int(node_id)}"


def _all_series_dict(all_files_list, args):
    # Extract nodes names for dictionary of features series
    node_names = [file.split("/")[-1].split("_")[0] for file in all_files_list]
    # Build dictionary to use for feature series of each node
    series_dict = {
        feature: {node_name: [] for node_name in node_names}
        for feature in args.attack_classification_features
    }
    # For each node get all the feature series and put it in the corresponding dictionary entry
    for file in all_files_list:
        node_name = file.split("/")[-1].split("_")[0]
        for feature in args.attack_classification_features:
            series = _get_series(file, feature)
            series_dict[feature][node_name] = series
    return series_dict


def _all_dios_dict(files, args):
    # Extract nodes names for dictionary of features series
    node_names = [file.split("/")[-1].split("_")[0] for file in files]
    total_timesteps = int(args.simulation_time / args.time_window)
    # Build dictionary where first entry is the node, and
    dios_dict = {
        node_name: {time_step: [] for time_step in range(total_timesteps)}
        for node_name in node_names
    }
    # For each node get all the featrue series and put it in the corresponding dictionary entry
    for file in files:
        node_name = file.split("/")[-1].split("_")[0]
        for time_step in range(total_timesteps):
            row = _get_row_list(file, time_step)
            series = []
            for node_id in row:
                if node_id == 0:
                    break
                series.append(_get_node_name_from_id(node_id))
            dios_dict[node_name][time_step] = series
    return dios_dict


def _create_trains_and_tests(all_files_list, features, size):
    # Get node names
    node_names = [file.split("/")[-1].split("_")[0] for file in all_files_list]
    # Create empty dictionaries for trains,tests and predictions for each feature and each node
    trains_dict = {
        feature: {node_name: [] for node_name in node_names} for feature in features
    }
    histories_dict = {
        feature: {node_name: [] for node_name in node_names} for feature in features
    }
    tests_dict = {
        feature: {node_name: [] for node_name in node_names} for feature in features
    }
    predictions_dict = {
        feature: {node_name: [] for node_name in node_names} for feature in features
    }
    conf_intervals_dict = {
        feature: {node_name: [] for node_name in node_names} for feature in features
    }
    # For each file fill the corresponding dictionary entry
    for file in all_files_list:
        node_name = file.split("/")[-1].split("_")[0]
        # Get time series of the chosen feature
        for feature in features:
            series = _get_series(file, feature)
            X = np.squeeze(series.values)
            # Split into first train and remaining test
            train, test = X[0:size], X[size : len(X)]
            # Append train and test to the list of all trains and tests
            trains_dict[feature][node_name] = train
            histories_dict[feature][node_name] = train
            tests_dict[feature][node_name] = test
            predictions_dict[feature][node_name] = []
            conf_intervals_dict[feature][node_name] = []

    return (
        trains_dict,
        tests_dict,
        histories_dict,
        predictions_dict,
        conf_intervals_dict,
    )


def _get_nodes_in_train(nodes_stats, node_names, train_size):
    list_nodes = []
    # Get all nodes that transmitted at least one packet during training
    for node_id in node_names:
        train = nodes_stats[node_id].head(train_size)
        if (
            train["# DIO txd"].sum()
            + train["# DIS txd"].sum()
            + train["# DAO txd"].sum()
            + train["# APP txd"].sum()
            > 0
        ):
            list_nodes.append(node_id)
    print(f"list_nodes in train: {list_nodes}")
    return list_nodes


def _extract_list_nodes(original_net_traffic, size, args):
    # From original traffic get training set
    data = original_net_traffic[
        original_net_traffic[args.time_feat_micro] < size * args.time_window * 1e6
    ]
    # From training set get list of nodes trasmitting at least 1 packet
    list_nodes = data["TRANSMITTER_ID"].value_counts().index.to_list()
    list_nodes = [node for node in list_nodes if "SENSOR" in node or "SINKNODE" in node]
    list_nodes = [node.split("-")[-1] for node in list_nodes]
    print(f"list_nodes in train: {list_nodes}")
    return list_nodes


def _extract_nodes_dests(original_net_traffic, size, args):
    # From original traffic get training set
    data = original_net_traffic[
        original_net_traffic[args.time_feat_micro] < size * args.time_window * 1e6
    ]
    # From training set get list of nodes trasmitting at least 1 packet
    list_nodes = data["TRANSMITTER_ID"].value_counts().index.to_list()
    list_nodes = [node for node in list_nodes if "SENSOR" in node or "SINKNODE" in node]
    list_nodes = [node.split("-")[-1] for node in list_nodes]
    # Create empty dictionary of nodes and dests
    dict_nodes_dests = {node: [] for node in list_nodes}
    # Replace names in data with only numbers
    names = data["TRANSMITTER_ID"].str.split("-", n=1, expand=True)
    data.drop(columns=["TRANSMITTER_ID"], inplace=True)
    data["TRANSMITTER_ID"] = names[1]
    # For each node get the corresponding destinations
    for node in list_nodes:
        condition = (data["TRANSMITTER_ID"] == node) & (
            (data["CONTROL_PACKET_TYPE/APP_NAME"] == "DAO")
            | (data["PACKET_TYPE"] == "Sensing")
        )
        receivers = data[condition]["RECEIVER_ID"].value_counts().index.to_list()
        dict_nodes_dests[node] = receivers
    print(f"dict_nodes_dests in train: {dict_nodes_dests}")

    return dict_nodes_dests

def main():
    tic_main = tm.perf_counter()
    args = settings_parser.arg_parse()

    # Setting file name for output txt
    if not os.path.exists(
        os.path.join(
            os.getcwd(),
            "log",
            args.output_dir,
            args.scenario,
            str(int(args.simulation_time)),
        )
    ):
        os.makedirs(
            os.path.join(
                os.getcwd(),
                "log",
                args.output_dir,
                args.scenario,
                str(int(args.simulation_time)),
            )
        )
    output_filename = os.path.join(
        os.getcwd(),
        "log",
        args.output_dir,
        args.scenario,
        str(int(args.simulation_time)),
        args.chosen_simulation.split("-")[-1] + ".txt",
    )
    output_file = open(output_filename, "w", encoding="utf8")
    output_file.write(
        f"Scenario: {args.scenario} - Simulation {args.chosen_simulation.split('-')[-1]}\n"
    )
    # Getting data path
    filenames = glob.glob(
        os.path.join(
            os.getcwd(),
            args.feat_folders,
            args.scenario,
            str(int(args.simulation_time)),
            "*",
        )
    )
    filenames.sort()
    all_files = _get_files(filenames)
    all_files = [item for item in all_files if args.chosen_simulation in item]
    # Get DAOs
    dao_file = [item for item in all_files if "DAO" in item]
    daos = pd.read_csv(dao_file[0])
    # Pick file containing DIOs
    dio_files = [item for item in all_files if "neighbor" in item]
    dios = _all_dios_dict(dio_files, args)

    # Remove file containing DAOs and neighbors
    all_files = [
        item
        for item in all_files
        if ("SENSOR" in item or "SINKNODE") and "stats" in item
    ]
    all_series_attack_classification = _all_series_dict(all_files, args)

    # Create node_stats with columns node_id and time series of statistics for each node
    nodes_stats = {}
    node_names = []
    for file in all_files:
        node_id = file.split("/")[-1].split("_")[0]
        node_names.append(node_id)
        stats = pd.read_csv(file)
        nodes_stats[node_id] = stats

    # Select feature to be regressed
    feature = args.feature_for_anomalies
    features = ["# DIO rcvd", "# APP rcvd", "# DAO txd"]
    # Set training steps size and precision of confidence interval
    size = 30
    alpha = args.alpha

    # Extract lists containing series for each device
    trains, tests, histories, predictions, conf_intervals = _create_trains_and_tests(
        all_files, features, size
    )
    list_communicating_nodes_from_train = _get_nodes_in_train(
        nodes_stats, node_names, size
    )
    # list_communicating_nodes_from_train = extract_list_nodes(original_net_traffic, size, args)
    # dict_nodes_dests_from_train = extract_nodes_dests(original_net_traffic, size, args)
    node_names = [file.split("/")[-1].split("_")[0] for file in all_files]
    # List to be filled with time performances
    list_pred_times = []

    # Get length of train and test series and number of nodes
    test_length = len(tests[features[0]][node_names[0]])
    train_length = len(trains[features[0]][node_names[0]])
    n_nodes = len(node_names)

    # Through the length of test compute predictions in parallel
    for time_step in range(test_length):
        # Compute corresponding time in seconds to know when each anomaly is raised
        time_seconds = (time_step + train_length) * args.time_window + args.time_window
        # Define list of nodes that will be checked by attack classifier
        list_nodes_raising_anomaly = {feature: [] for feature in features}
        list_nodes_raising_anomaly_full_name = {feature: [] for feature in features}
        bool_raise_anomaly = False
        tic_arima = tm.perf_counter()
        for feature in features:
            print(
                f"\rARIMA on time_step: {time_seconds}/"
                f"{args.simulation_time} and feature: {feature}",
                end="\r",
            )
            if time_step == test_length - 1:
                print()
            # For each considered device compute forecast using arima and check for  anomaly
            # parallelization
            with Parallel(n_jobs=12) as parallel:
                output_parallelization = parallel(
                    delayed(_arima_fit)(
                        histories,
                        feature,
                        node_index,
                        all_files,
                        tests,
                        time_step,
                        time_seconds,
                        alpha,
                    )
                    for node_index in range(n_nodes)
                )

            for node_index in range(n_nodes):
                node_name = all_files[node_index].split("/")[-1].split("_")[0]
                # Set history of this node for next prediction
                obs = tests[feature][node_name][time_step]
                histories[feature][node_name] = np.append(
                    histories[feature][node_name], obs
                )
                histories[feature][node_name] = histories[feature][node_name][1:]

                list_pred_times.append(output_parallelization[node_index][0])
                predictions[feature][node_name].append(
                    output_parallelization[node_index][1]
                )
                conf_intervals[feature][node_name].append(
                    output_parallelization[node_index][2]
                )
                if not output_parallelization[node_index][3] == []:
                    list_nodes_raising_anomaly[feature].append(
                        output_parallelization[node_index][3]
                    )
                    list_nodes_raising_anomaly_full_name[feature].append(
                        output_parallelization[node_index][4]
                    )
            if not (
                list_nodes_raising_anomaly
                == {"# DIO rcvd": [], "# APP rcvd": [], "# DAO txd": []}
            ):
                bool_raise_anomaly = True
            else:
                bool_raise_anomaly = False
        toc_arima = tm.perf_counter()
        # If anomaly is raised get neighborhood, check dodag and get features for classification
        if bool_raise_anomaly:
            neighborhoods_dict = {feature: [] for feature in features}
            neighborhoods_full_name_dict = {feature: [] for feature in features}
            nodes_to_check_dict = {feature: [] for feature in features}
            nodes_to_check_full_name_dict = {feature: [] for feature in features}

            for feature in features:
                (
                    neighborhoods_full_name_dict[feature],
                    neighborhoods_dict[feature],
                ) = extract_neighborhood(
                    dios,
                    list_nodes_raising_anomaly_full_name[feature],
                    time_seconds,
                    args,
                )
                # Nodes to check are the ones that have raised anomalies and their neighbours
                nodes_to_check_dict[feature] = (
                    list_nodes_raising_anomaly[feature] + neighborhoods_dict[feature]
                )
                nodes_to_check_full_name_dict[feature] = (
                    list_nodes_raising_anomaly_full_name[feature]
                    + neighborhoods_full_name_dict[feature]
                )
            # Extract single list containing all nodes that raised an anomaly in either feature
            single_list_nodes_raising_anomaly = [
                node
                for feature_anom in features
                for node in list_nodes_raising_anomaly[feature_anom]
            ]
            single_list_nodes_raising_anomaly = list(
                set(single_list_nodes_raising_anomaly)
            )
            # Print anomaly and nodes involved in the output file
            output_file.write(
                f"Anomaly raised at time {time_seconds}. "
                f"Devices involved: {list_nodes_raising_anomaly}\n"
            )
            # Extract single list containing all neighbours of nodes that raised an anomaly
            single_list_neighbours = [
                node
                for feature_anom in features
                for node in neighborhoods_dict[feature_anom]
            ]
            single_list_neighbours = list(set(single_list_neighbours))
            # Extract single list of anomalous nodes (nodes raising anomaly + neighbours)
            anomalous_nodes = [
                node
                for feature_anom in features
                for node in nodes_to_check_dict[feature_anom]
            ]
            anomalous_nodes = list(set(anomalous_nodes))
            # Extract single list of anomalous nodes (nodes raising anomaly + neighbours)
            anomalous_nodes_full_name = [
                node
                for feature_anom in features
                for node in nodes_to_check_full_name_dict[feature_anom]
            ]
            anomalous_nodes_full_name = list(set(anomalous_nodes_full_name))
            # Check if dodag changed or not

            dodag_changed, nodes_changing = extract_dodag_before_after(
                daos,
                single_list_nodes_raising_anomaly,
                single_list_neighbours,
                time_seconds,
                args,
            )

            # Classify the attack
            classify_attack_from_dodag(
                all_series_attack_classification,
                anomalous_nodes_full_name,
                nodes_changing,  # anomalous_nodes_full_name,
                time_step + train_length,
                dodag_changed,
                list_communicating_nodes_from_train,
                output_file,
                args,
            )

    # Closes txt file
    output_file.close()
    # Plot prediction times using box plot
    toc_main = tm.perf_counter()
    print(f"Whole main took: {toc_main - tic_main}")


def _arima_fit(
    histories, feature, node_index, all_files, tests, time_step, time_seconds, alpha
):
    node_name = all_files[node_index].split("/")[-1].split("_")[0]
    node_full_name = all_files[node_index].split("/")[-1].split("_")[0]
    conf_int = [[-0.1, 0.1] for x in range(1)]
    output = 0
    # Monitor also time efficiency
    tic = tm.perf_counter()
    # Try to fit arima since it may return errors depending on matrices rank
    try:
        warnings.filterwarnings("ignore")
        model = pm.auto_arima(
            histories[feature][node_name],
            start_p=1,
            start_q=1,
            test="adf",  # use adftest to find optimal 'd'
            max_p=3,
            max_q=3,  # maximum p and q
            m=1,  # frequency of series
            d=None,  # let model determine 'd'
            seasonal=False,  # No Seasonality
            start_P=0,
            D=0,  # Minimum differencing order
            trace=False,
            error_action="ignore",
            suppress_warnings=True,
            stepwise=True,
        )
        output, conf_int = model.predict(n_periods=1, return_conf_int=True, alpha=alpha)
    except:
        pass
    toc = tm.perf_counter()
    single_pred_time = toc - tic
    # Append prediction and confidence interval to the corresponding dictionary entry
    # If real value is outside confidence range it is considered an anomaly
    if (
        tests[feature][node_name][time_step] < conf_int[0][0]
        or tests[feature][node_name][time_step] > conf_int[0][1]
    ):
        # Update list of nodes to be checked and raise the anomaly
        node_raising_anomaly = node_name
        node_raising_anomaly_full_name = node_full_name
        print(
            f"Anomaly found in node {node_name} at time {time_seconds} for feature {feature}"
        )
    else:
        node_raising_anomaly = []
        node_raising_anomaly_full_name = []

    return (
        single_pred_time,
        output,
        conf_int,
        node_raising_anomaly,
        node_raising_anomaly_full_name,
    )


if __name__ == "__main__":
    main()
