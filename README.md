# Malware Feature Extraction Tool

A Python-based tool for extracting and organizing metadata and raw features from Windows PE executable files for malware analysis and machine learning applications.

## Overview

This project provides utilities to:
- Scan directories containing malware and benign executables
- Generate metadata CSV files with file paths, SHA256 hashes, classifications, and labels
- Extract raw PE features using the EMBER feature extractor
- Export features to JSONL format for machine learning pipelines

## Requirements

```
python == 3.6.13
pathlib
hashlib
csv
json
logging
argparse
```
Install EMBER from [repo](https://github.com/7h3cyb3rm0nk/ember) (instructions inside the repo)
**nix flake for python 3.6.13:
run this inside ember repo to initialize a working development environment**
```
nix develop github:7h3cyb3rm0nk/flakes#ember-shell
```


## Project Structure

```
.
└── scripts
    ├── collect_metadata.py   # for collecting metadata from exe files and saves it to metadata/metadata.csv
    └── generare_features_json.py # generates raw features jsonl file from metadata/metadata.csv

```

## Usage

### 1. Generate Metadata CSV

The metadata generator script scans directories and creates CSV files with file information.

#### Generate Combined Metadata (Malware + Benign)

```bash
python collect_metadata.py /path/to/executables --benign-name benign
```

#### Generate Malware-Only Metadata

```bash
python collect_metadata.py /path/to/executables --malware-only --benign-name benign
```

#### Generate Benign-Only Metadata

```bash
python collect_metadata.py /path/to/executables --benign-only --benign-name benign
```

#### Enable Verbose Logging

```bash
python collect_metadata.py /path/to/executables --benign-name benign --verbose
```

### 2. Extract Raw Features

After generating metadata, extract PE features:

```bash
python generare_features_json.py
```

This reads `metadata/metadata.csv` and generates `json/raw_features.jsonl` with EMBER features.

## Command Line Arguments

### collect_metadata.py

| Argument | Short | Description | Required |
|----------|-------|-------------|----------|
| `path` | - | Root path containing executable files | Yes |
| `--benign-name` | `-d` | Name of the benign directory | Yes |
| `--malware-only` | `-m` | Create malware-only metadata | No |
| `--benign-only` | `-b` | Create benign-only metadata | No |
| `--verbose` | `-v` | Enable verbose debug output | No |

## Output Format

### Metadata CSV

The generated CSV files contain the following columns:

- `file_path`: Full path to the executable file
- `sha256`: SHA256 hash of the file
- `avclass`: Classification/family name (from parent directory)
- `label`: Binary label (1 for malware, 0 for benign)

Example:
```csv
file_path,sha256,avclass,label
/path/to/trojan.exe,abc123...,trojan,1
/path/to/clean.exe,def456...,benign,0
```

### Raw Features JSONL

Each line in the JSONL file contains:
- All EMBER raw PE features (imports, exports, sections, headers, etc.)
- `label`: Binary classification label
- `avclass`: Malware family or benign classification

## Directory Structure Requirements

Your dataset should be organized as follows:

```
dataset_root/
├── benign/              # Benign executables
│   ├── app1.exe
│   └── app2.exe
├── trojan/              # Malware family directories
│   ├── sample1.exe
│   └── sample2.exe
├── ransomware/
│   └── sample3.exe
└── ...
```

The script uses parent directory names as the `avclass` field.

## Key Functions

### collect_metadata.py

- `get_sha256_hash(path)`: Computes SHA256 hash of a file
- `get_exe_file_paths(path, include, exclude)`: Recursively finds all `.exe` files
- `create_malware_metadata(path, include, exclude)`: Generates malware metadata CSV
- `create_benign_metadata(path, include, exclude)`: Generates benign metadata CSV
- `create_metadata_csv(path, benign_path_name)`: Generates combined metadata CSV

### generare_features_json.py

- `write_metadata_to_json(csvpath)`: Extracts EMBER features and writes to JSONL


## Logging

Logging is configured at two levels:
- **INFO** (default): Shows major operations and progress
- **DEBUG** (with `--verbose`): Shows detailed operation information




## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style conventions
- Functions include proper docstrings
- Error handling is implemented
- Logging statements are appropriate

## Acknowledgments

This project uses the [EMBER](https://github.com/elastic/ember) feature extraction framework developed.
