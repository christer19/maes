import argparse
import json
import os
import yaml

from collections import defaultdict

# Option for user to specify which category they want to score on
parser = argparse.ArgumentParser()
parser.add_argument('--category', action="store", default="mature_soc")
args = parser.parse_args()

if args.category not in ('mature_soc', 'mssp', 'immature_soc'):
    raise ValueError("Invalid category, please use category from provided list.")

# Import scoring information
score_file = args.category + '.yml'
with open(score_file, 'r') as f:
    scoring = yaml.safe_load(f)


# Fetch all result json files from directory
data_repo = './data/'
result_files = os.listdir(data_repo)


def score_substep(data):
    detect_data = data['Detections']
    substep_scores = []
    
    # If SubStep was N/A, return a score of 0
    if detect_data[0]['DetectionType'] == 'N/A':
        return [0.0]
    
    for val in detect_data:
        detection_type = val['DetectionType']
        dt_score = scoring['detection'][detection_type]
        detection_modifiers = sorted(val['Modifiers'])
        # Account for Residual Artifact and Host Interrogation Results
        if any(x in detection_modifiers for x in {'Host Interrogation', 'Residual Artifact'}):
            dt_score = 3.0
        if len(detection_modifiers) != 0:
            dt_mod_scores = [scoring['modifier'][m] for m in detection_modifiers]
            dt_score = dt_score * min(dt_mod_scores)
        substep_scores.append(dt_score)
    
    return substep_scores


final_data = defaultdict(float)
    

# Parse files one at a time
for rfile in result_files:
    vendor = rfile.replace('.1.APT29.1_Results.json', '')
    with open(data_repo + rfile,'r') as f:
        data = json.load(f)
        technique_data = data['Techniques']
        # For each technique, analyze substeps
        for technique in technique_data:
            steps_data = technique['Steps']
            for sd in steps_data:
                # Score substep based on all detections
                substep_scores = score_substep(sd)
                final_data[vendor] += max(substep_scores)


# Sort and print vendors based on score
final_data = {k: v for k, v in sorted(final_data.items(), key=lambda item: item[1], reverse=True)}
for name,info in final_data.items():
    print(name + ': ' + str(info))