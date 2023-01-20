# DETONAR on Border Router logs

This is an extension of the original implementation of DETONAR, to make it possible to run DETONAR on Cooja logs from a border router rather than the full network traffic.


## Running the whole DETONAR pipeline

Given a dataset, the run_pipeline-file will:
* Parse the dataset by running parse_statistics.py
* Run the IDS over the parsed files using new_arima_ids.py
* Produce two files:
    * A summary with statistics for all simulations
    * A file with the specific attacks and attackers for each simulation

Run for example:

    python3 run_pipeline.py --data_dir="dataset/Dataset_Random" --simulation_time=24000

## Running the separate steps
The different steps can also be run separately for only one simulation:

### Parsing statistics:

    python3 parse_statistics.py --scenario="Blackhole" --chosen_simulation="00001" --simulation_time=24000 --time_window=600 --data_dir="dataset/Dataset_Random"

### Running IDS:

    python3 new_arima_ids.py --scenario="Sinkhole" --chosen_simulation="00001" --simulation_time=24000 --time_window=600 --data_dir="dataset/Dataset_Random" --output_dir="output"


### Summarizing result files
If you have a directory containing output-files, you can summarize the results of that directory:

    python3 summarize_output_files.py --data_dir="dataset/Dataset_Random" --simulation_time=24000 --time_window=600 --output_dir="output"
