import argparse


def arg_parse():
    parser = argparse.ArgumentParser(description="DETONAR")

    # Parameters statistics parsing
    parser.add_argument(
        "--data_dir",
        type=str,
        default="dataset/Dataset_Random",
        help="root path to data directory",
    )
    parser.add_argument(
        "--scenario", type=str, default="Legitimate", help="name of attack/legitimate"
    )
    parser.add_argument(
        "--n_features", default=14, type=int, help="number of features used"
    )
    parser.add_argument(
        "--time_start", default=600, type=int, help="time window in seconds"
    )
    parser.add_argument(
        "--time_window", default=600, type=int, help="time window in seconds"
    )
    parser.add_argument(
        "--simulation_time",
        default=24000,
        type=int,
        help="time of the simulation in seconds",
    )
    parser.add_argument(
        "--cumulative_sum",
        default="False",
        type=str,
        help="set to true to use cumulative sum of features",
    )
    parser.add_argument(
        "--out_feat_files",
        default="log/features_extracted/",
        type=str,
        help="folder for features files to be stored",
    )
    parser.add_argument(
        "--single_sim",
        default="",
        type=str,
        help="If not empty run feature extraction on a single simulation (Just for DEBUG purposes)",
    )
    parser.add_argument(
        "--time_feat_micro",
        default="TIME",
        type=str,
        help="Feature used to check time of a packet in micro seconds",
    )
    parser.add_argument(
        "--time_feat_sec",
        default="TIME",
        type=str,
        help="Feature used to check time of a packet in seconds",
    )
    parser.add_argument(
        "--max_nr_neighbors",
        default=15,
        type=int,
        help="Feature used for creating the time series of neighbor-lists",
    )

    # Parameters feature regressor
    parser.add_argument(
        "--model",
        default="random forest",
        type=str,
        help="possibilities: svr - decision tree - random forest - linear",
    )
    parser.add_argument(
        "--feat_folders",
        default="log/features_extracted/",
        type=str,
        help="folder for features files to be stored",
    )
    parser.add_argument(
        "--normalization",
        default="False",
        type=str,
        help="set to true to normalize features used for regression",
    )
    parser.add_argument(
        "--standardization",
        default="True",
        type=str,
        help="set to true to standardize features used for regression",
    )
    parser.add_argument(
        "--lag_val", default=30, type=int, help="size of window used for regression"
    )
    parser.add_argument(
        "--prediction_window",
        default=1,
        type=int,
        help="number of future values predicted",
    )
    parser.add_argument(
        "--alpha", default=0.0001, type=float, help="alpha used for regression"
    )
    parser.add_argument(
        "--seq_per_series",
        default=5,
        type=int,
        help="number of sequences extracted from each series used for training",
    )
    parser.add_argument(
        "--max_depth", default=10, type=int, help="max depth of regression tree"
    )
    parser.add_argument(
        "--train_ratio",
        default=0.8,
        type=float,
        help="percentage of csv files used for training",
    )
    parser.add_argument(
        "--features_to_fit",
        default=["# APP rcvd", "# APP txd"],
        nargs="+",
        help="features to be fitted",
    )
    parser.add_argument(
        "--feature_for_anomalies",
        default="# APP rcvd",
        type=str,
        help="feature used for anomalies detection",
    )
    parser.add_argument(
        "--all_features",
        default=[
            "# DIO rcvd",
            "# APP rcvd",
            "# DAO txd",
            "# DIO txd",
            "# DIS txd",
            "# APP txd",
            "# DIS txd",
            "incoming_vs_outgoing",
            "# ranks",
            "version_changed",
            "current_rank",
            "current_version",
            "nr_neighbours",
            "neighbors",
            "parent_changed",
        ],
        nargs="+",
        help="features to be fitted",
    )
    parser.add_argument(
        "--output_imgs_folder",
        default="log/images/non_cumulative/",
        type=str,
        help="folder for features files to be stored",
    )
    parser.add_argument(
        "--chosen_simulation",
        default="",
        type=str,
        help="simulation to be used for anomaly detection",
    )
    parser.add_argument(
        "--output_dir",
        default="output",
        type=str,
        help="folder for output text-files to be stored",
    )

    # Parameters attack classification
    parser.add_argument(
        "--attack_classification_features",
        default=[
            "# DIO rcvd",
            "# APP rcvd",
            "# DAO txd",
            "# DIO txd",
            "# DIS txd",
            "# APP txd",
            "current_rank",
            "current_version",
            "rank_change_time",
            "version_change_time",
            "incoming_vs_outgoing",
            "changed_parent",
        ],
        nargs="+",
        help="features used for attack classification",
    )

    # Parameters for running workflow

    args = parser.parse_args()

    return args
