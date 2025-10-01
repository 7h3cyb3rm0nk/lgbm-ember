from pathlib import Path
from typing import List, Union
import csv

from ember import PEFeatureExtractor
import ember
import logging

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)



def get_exe_file_paths(
    path: str, 
    include: Union[List[str], None] = None, 
    exclude: Union[List[str], None] = None
    ) -> List[Path]:
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
                exe_paths.append(subdir)

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

    try:
        
        malware_file_paths = get_exe_file_paths(path, include=include, exclude=exclude)
        with open("malware_metadata.csv", "w", newline='') as csvfile:
            logger.debug("opening malware_metadata.csv")
            writer = csv.writer(csvfile)
            rows = [(file_sha256, file_sha256.stem, 1) for file_sha256 in malware_file_paths ]
            writer.writerow(["name","sha256", "label"])
            writer.writerows(rows)
            logger.debug(f"wrote {len(rows)} to malware_metadata.csv")
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

    try:
        benign_file_paths = get_exe_file_paths(path, include=include, exclude=exclude)
        with open("benign_metadata.csv", "w", newline='') as csvfile:
            logger.debug("opening benign_metadata.csv")
            writer = csv.writer(csvfile)
            rows = [(file_sha256, file_sha256.stem, 0) for file_sha256 in benign_file_paths ]
            writer.writerow(["name","sha256", "label"])
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

   


def generate_malware_json(malware_paths: List[Path]):
    pass
    #TODO


def process_malware_sample(malware_file: Path) -> str:
    pass
    #TODO



def create_metadata_csv(path: str, benign_path_name: str):
    try:
        benign_include = [benign_path_name]
        malware_exclude = [benign_path_name]
        
        malware_file_paths = get_exe_file_paths(path, exclude=malware_exclude)
        benign_file_paths = get_exe_file_paths(path, include=benign_include)
        with open("metadata.csv", "w", newline='') as csvfile:
            logger.debug("opening metadata.csv")
            writer = csv.writer(csvfile)
            malware_rows = [(file_sha256, file_sha256.stem, 1) for file_sha256 in malware_file_paths ]
            benign_rows = [(file_sha256, file_sha256.stem, 0) for file_sha256 in benign_file_paths]
            writer.writerow(["name","sha256", "label"])
            
            writer.writerows(malware_rows)
            writer.writerows(benign_rows)

            logger.debug(f"wrote {len(malware_rows)+len(benign_rows)} rows to metadata.csv")


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
    

create_malware_metadata("../samples/3.Normal_exe/", exclude=["benign"])
create_benign_metadata("../samples/3.Normal_exe/", include = ["benign"])
create_metadata_csv("../samples/3.Normal_exe/", benign_path_name="benign")
