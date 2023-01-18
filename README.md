# DETONAR on Cooja logs

This is an extension of the original implementation of DETONAR, to adjust it to work on Cooja logs. You can run DETONAR the same way as originally, or use the pipeline which runs all steps for you:

## Running the whole DETONAR pipeline

Given a dataset, the run_pipeline-file will:

* Extract features from all files in the dataset by running feature_extractor.py
* Run the IDS over the feature files using new_arima_ids.py
* Produce two files:
   * A summary with statistics for all simulations
   * A file with the specific attacks and attackers for each simulation

Run for example:

    python3 run_pipeline.py --data_dir="dataset/Dataset_Random" --simulation_time=24000


## Running separate steps

### Feature extraction

    python feature_extractor.py --data_dir="dataset/Dataset_Random" --scenario="Blackhole" --out_feat_files="log/features_extracted/"


### Run IDS

    python new_arima_ids.py --scenario="Blackhole" --chosen_simulation="00001" --simulation_time=24000 --time_window=600

### Summarize result files
If you have a directory containing output-files, you can summarize the results of that directory:

    python3 summarize_output_files.py --data_dir="dataset/Dataset_Random" --output_dir="output" --simulation_time=24000 --time_window=600