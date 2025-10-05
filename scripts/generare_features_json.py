import json
import ember
from pathlib import Path
from typing import List, Dict, Union, Tuple
import logging

import csv

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

def write_metadata_to_json(csvpath: Path):
    json_dir = Path("json")
    json_dir.mkdir(parents=True, exist_ok=True)
    with open(csvpath) as csvfile:
        reader = csv.DictReader(csvfile)
        jsonfile = open(json_dir/Path("raw_features.jsonl"), "w")
        for row in reader:
            path = row["file_path"]
            with open(path, "rb") as pefile:
                bytez  = pefile.read()
                extractor = ember.PEFeatureExtractor()
                raw_features = extractor.raw_features(bytez)
                raw_features["label"] = row["label"]
                raw_features["avclass"] = row["avclass"]
                logger.debug(f'extracting raw features of {row["file_path"]}')
                json.dump(raw_features, jsonfile)
                jsonfile.write('\n')
                
    jsonfile.close()

write_metadata_to_json(Path("./metadata/metadata.csv"))
