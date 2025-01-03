import argparse
import hashlib
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Verify file integrity by comparing hashes.")
    parser.add_argument("filepath", type=str, help="Path to the file to be verified.")
    parser.add_argument("-a", "--algorithm", type=str, default="sha256",
                        choices=["sha256", "sha1", "md5"],
                        help="Hash algorithm to use (default: sha256).")
    parser.add_argument("-c", "--compare_hash", type=str,
                        help="Hash value to compare against. If not provided, only calculate the hash.")
    return parser


def calculate_hash(filepath, algorithm="sha256"):
    """
    Calculates the cryptographic hash of a file.

    Args:
        filepath (str): Path to the file.
        algorithm (str, optional): The hash algorithm to use. Defaults to "sha256".

    Returns:
        str: The calculated hash value as a hexadecimal string.
        None: If an error occurs during file processing.
    """
    try:
        # Security best practice: Read file in binary mode
        with open(filepath, 'rb') as f:
            hasher = hashlib.new(algorithm)
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except Exception as e:
        logging.error(f"Error calculating hash for {filepath}: {e}")
        return None


def main():
    """
    Main function to execute the file hash verification.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    filepath = args.filepath
    algorithm = args.algorithm
    compare_hash = args.compare_hash

    # Validate filepath exists
    if not os.path.exists(filepath):
        logging.error(f"Error: The file '{filepath}' does not exist.")
        sys.exit(1)

    # Input validation for filepaths
    if not isinstance(filepath, str):
        logging.error(f"Error: Invalid filepath '{filepath}'. Please provide a valid path.")
        sys.exit(1)
    
    calculated_hash = calculate_hash(filepath, algorithm)
    if calculated_hash is None:
        sys.exit(1)

    logging.info(f"Calculated {algorithm} hash for {filepath}: {calculated_hash}")

    if compare_hash:
        # Input validation for compare_hash
        if not isinstance(compare_hash, str):
            logging.error(f"Error: Invalid hash '{compare_hash}'. Please provide a valid hash value.")
            sys.exit(1)

        if calculated_hash.lower() == compare_hash.lower():
            logging.info("Hash values match. File integrity verified.")
        else:
            logging.warning("Hash values do not match. File integrity check failed.")


if __name__ == "__main__":
    # Example usage:
    # To calculate a hash:
    # python main.py test.txt
    # To compare a hash:
    # python main.py test.txt -c <known_hash>
    # python main.py test.txt -a sha1 -c <known_sha1_hash>
    # python main.py test.txt -a md5 -c <known_md5_hash>
    
    main()