from pathlib import Path
from typing import List, Union, Tuple
import csv
import hashlib
import argparse

from ember import PEFeatureExtractor
import ember
import logging


logger = logging.getLogger(__name__)

def get_sha256_hash(path: Path) -> str:
    """
    Returns the sha256 hash of a file
    Args:
        path: path to the file
    Returns:
        str: sha256 hash of the file
    """
    sha256_hash = hashlib.sha256()
    with open(str(path), "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()





def get_exe_file_paths(
    path: str, 
    include: Union[List[str], None] = None, 
    exclude: Union[List[str], None] = None
    ) -> List[Tuple[Path, str]]:
    """
    Get all exe file paths from the subdirectories in the dataset directory
    Args:
        path: Root path containing subdirectories which contain exe files
        include: directory names to only include
        exclude: directory names to exclude
    Returns:
        List of Path objects for exe file
    Raises:
        FileNotFoundError: If the path doesn't exist
        NotADirectoryError: If the path is not a directory
    """
    try:
        dir = Path(path)
        if not dir.exists():
            raise FileNotFoundError(f"{dir} does not exist")
        if not dir.is_dir():
            raise NotADirectoryError(f"{dir} is not a directory")
        exe_paths = []


        for subdir in dir.iterdir():

            if exclude and subdir.name in exclude:
                logger.debug(f"skipping directory {subdir} due to exclude list")
                continue
            if include and subdir.name not in include:
                logger.debug(f"skipping directory {subdir} due to include list")
                continue
            
            
            if subdir.is_dir():
                try:
                    new_include = None if include is None else include.copy()
                    if new_include and subdir.name in new_include:
                        new_include.remove(subdir.name)
                        if not new_include:
                            new_include = None

                    exe_paths_in_subdir = get_exe_file_paths(str(subdir), include=new_include, exclude=exclude)
                    exe_paths.extend(exe_paths_in_subdir)

                except PermissionError:
                    logger.warning(f"permission denied accessing {subdir}")
            elif subdir.is_file() and subdir.suffix.lower() == ".exe":
                sha256_hash = get_sha256_hash(subdir)
                exe_paths.append((subdir, sha256_hash, subdir.parent.stem))

        return exe_paths

    except FileNotFoundError:
        raise 
    except NotADirectoryError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


def create_malware_metadata(
    path: str,
    include: Union[List[str], None] = None, 
    exclude: Union[List[str], None] = None
    ):
    """
    write metadata (file_path, sha256, avclass, label) of malware exes into a csv file
    Args:
        path: Root path containing subdirectories which contain malware files
        include: directory names to only include
        exclude: directory names to exclude
    Raises:
        FileNotFoundError: If the path doesn't exist
        NotADirectoryError: If the path is not a directory
        IOError: If the write operation fails


    """

    try:
        
        malware_file_paths = get_exe_file_paths(path, include=include, exclude=exclude)
        output_dir = Path("metadata")
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(f"{output_dir}/malware_metadata.csv", "w", newline='') as csvfile:
            logger.debug(f"opening {output_dir}/malware_metadata.csv")
            writer = csv.writer(csvfile)
            rows = [(file_path, sha256_hash, avclass, 1) for file_path, sha256_hash, avclass in malware_file_paths ]
            writer.writerow(["file_path","sha256", "avclass", "label"])
            writer.writerows(rows)
            logger.debug(f"wrote {len(rows)} to {output_dir}/malware_metadata.csv")
    except FileNotFoundError as e:
        logger.error(f"{e}")
        raise
    except NotADirectoryError as e:
        logger.error(f"{e}")
        raise

    except IOError:
        logger.error("failed to write malware metadata to a csv file")
        raise
    except Exception as e:
        logger.error(f"{e}")
        raise

    
def create_benign_metadata(
    path: str,
    include: Union[List[str], None] = None, 
    exclude: Union[List[str], None] = None
    ):
    """
    write metadata (file_path, sha256, avclass, label) of benign exes into a csv file
    Args:
        path: Root path containing subdirectories which contain benign files
        include: directory names to only include
        exclude: directory names to exclude
    Raises:
        FileNotFoundError: If the path doesn't exist
        NotADirectoryError: If the path is not a directory
        IOError: If the write operation fails


    """


    try:
        benign_file_paths = get_exe_file_paths(path, include=include, exclude=exclude)
        output_dir = Path("metadata")
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(f"{output_dir}/benign_metadata.csv", "w", newline='') as csvfile:
            logger.debug(f"opening {output_dir}/benign_metadata.csv")
            writer = csv.writer(csvfile)
            rows = [(file_path, sha256_hash,avclass, 0) for file_path, sha256_hash, avclass in benign_file_paths ]
            writer.writerow(["file_path","sha256", "avclass", "label"])
            writer.writerows(rows)
            logger.debug(f"wrote {len(rows)} to benign_metadata.csv")
    except FileNotFoundError as e:
        logger.error(f"{e}")
        raise
    except NotADirectoryError as e:
        logger.error(f"{e}")
        raise

    except IOError:
        logger.error("failed to write malware metadata to a csv file")
        raise
    except Exception as e:
        logger.error(f"{e}")
        raise


def create_metadata_csv(path: str, benign_path_name: str):
    try:
        benign_include = [benign_path_name]
        malware_exclude = [benign_path_name]
        
        malware_file_paths = get_exe_file_paths(path, exclude=malware_exclude)
        benign_file_paths = get_exe_file_paths(path, include=benign_include)

        output_dir = Path("metadata")
        output_dir.mkdir(parents=True, exist_ok=True)

        with open(f"{output_dir}/metadata.csv", "w", newline='') as csvfile:
            logger.debug(f"opening {output_dir}/metadata.csv")
            writer = csv.writer(csvfile)
            malware_rows = [(file_path, sha256_hash, avclass, 1) for file_path, sha256_hash, avclass in malware_file_paths ]
            benign_rows = [(file_path, sha256_hash, avclass, 0) for file_path, sha256_hash, avclass in benign_file_paths]
            writer.writerow(["file_path","sha256", "avclass", "label"])
            
            writer.writerows(malware_rows)
            writer.writerows(benign_rows)

            logger.debug(f"wrote {len(malware_rows)+len(benign_rows)} rows to {output_dir}/metadata.csv")


    except FileNotFoundError as e:
        logger.error(f"{e}")
        raise
    except NotADirectoryError as e:
        logger.error(f"{e}")
        raise

    except IOError:
        logger.error("failed to write malware metadata to a csv file")
        raise
    except Exception as e:
        logger.error(f"{e}")
        raise
    

# create_malware_metadata("../../../malwares/samples/3.Normal_exe/", exclude=["benign"])
# create_benign_metadata("../../../malwares/samples/3.Normal_exe/", include = ["benign"])
# create_metadata_csv("../../../malwares/samples/3.Normal_exe/", benign_path_name="benign")
def parse_arguments():
    parser = argparse.ArgumentParser(
        description = "Create metadata csv files for malware and benign executables"
    )
    parser.add_argument("path", help="Root path containing exe files")
    parser.add_argument('--malware-only','-m', action="store_true", help="create malware only metadata")
    parser.add_argument('--benign-only', '-b', action="store_true", help="create benign only metadata")
    parser.add_argument('--benign-name', '-d', default="benign", help="Name of the benign directory", required=True)
    parser.add_argument('--verbose', '-v',default=False, action="store_true", help="Enable verbose output")
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    


    if args.benign_only:
        create_benign_metadata(args.path, include=[args.benign_name])
    elif args.malware_only:
        create_malware_metadata(args.path, exclude=[args.benign_name])
    else:
        create_metadata_csv(args.path, args.benign_name)

if __name__ == '__main__':
    main()


