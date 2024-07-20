import os
import subprocess
import pefile
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# The functions `generate_import_hash`, `calculate_similarity`, `extract_utf16_strings_from_yara`, and `generate_ngram_index` remain the same.
def generate_import_hash(pe):
    """Generate an import hash for a given PE file."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return 'No Imports'
    imp_hash = hashlib.sha256()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        imp_hash.update(entry.dll.lower())
        for imp in entry.imports:
            if imp.name:
                imp_hash.update(imp.name)
            else:
                imp_hash.update(str(imp.ordinal).encode())
    return imp_hash.hexdigest()

def calculate_similarity(hash1, hash2):
    """Calculate the percentage similarity between two hashes."""
    matching_chars = sum(c1 == c2 for c1, c2 in zip(hash1, hash2))
    return matching_chars / len(hash1)  # assuming both hashes are of the same length

def extract_utf16_strings_from_yara(rule_file):
    """Extract and normalize UTF-16 strings from YARA rules."""
    utf16_strings = []
    with open(rule_file, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        matches = re.findall(r'\$.*? = "(.*?)" fullword wide', content)
        for match in matches:
            try:
                normalized_str = match.encode().decode('utf-16').encode('utf-8')
                utf16_strings.append(normalized_str)
            except UnicodeDecodeError:
                continue  # Skip strings that can't be decoded
    return utf16_strings

def generate_ngram_index(test_paths, rules_path, n=7):
    """Generate an inverted index of n-grams for the given files and UTF-16 strings in YARA rules."""
    index = {}
    # Adjusted to iterate over each path in the list of test paths
    for test_path in test_paths:
        # For YARA rules: Extract UTF-16 strings and add their n-grams to the index
        for rule_file in os.listdir(rules_path):
            utf16_strings = extract_utf16_strings_from_yara(os.path.join(rules_path, rule_file))
            for string in utf16_strings:
                for i in range(len(string) - n + 1):
                    ngram = string[i:i+n]
                    if ngram in index:
                        index[ngram].add('UTF-16 Rule: ' + rule_file)
                    else:
                        index[ngram] = {'UTF-16 Rule: ' + rule_file}
        # For files in each test_path: Add their n-grams to the index
        for root, _, files in os.walk(test_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    data = f.read()
                    for i in range(len(data) - n + 1):
                        ngram = data[i:i+n]
                        if ngram in index:
                            index[ngram].add(file_path)
                        else:
                            index[ngram] = {file_path}
    return index

# Keep the file_scan_task function unchanged.


def scan_directory_with_yara_and_hashes(directories, rules_path, import_hashes_path, ngram_index):
    potential_files = set()
    # Adjusted to iterate over each directory in the list of directories
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # Removed the check for '.exe' extension
                with open(file_path, 'rb') as f:
                    data = f.read()
                    for i in range(len(data) - 7 + 1):
                        if data[i:i+7] in ngram_index:
                            potential_files.add(file_path)
                            break

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(file_scan_task, file_path, rules_path, import_hashes_path, ngram_index) for file_path in potential_files]
        for future in as_completed(futures):
            future.result()  # Wait for all futures to complete

def file_scan_task(file_path, rules_path, import_hashes_path, ngram_index):
    match_found = False  # Initialize match_found flag for each file

    # Check YARA rules
    for rule_file in os.listdir(rules_path):
        if match_found:
            break  # Stop checking if a match has already been found
        rule_path = os.path.join(rules_path, rule_file)
        command = f"yara -r \"{rule_path}\" \"{file_path}\""
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            print(f"Malicious File Detected - {file_path}")
            match_found = True  # Set flag to true if a match is found
            # Send alert message
            send_alert_message(f'MALICIOUS ACTIVITY DETECTED - Cabin Crew VM detected malicious file: {file_path}')
            break  # Stop checking further if a match is found

    # Check import hashes only if no YARA match was found
    if not match_found:
        known_hashes = []
        for hash_file in os.listdir(import_hashes_path):
            hash_path = os.path.join(import_hashes_path, hash_file)
            with open(hash_path, 'r', encoding='utf-8', errors='ignore') as ihf:
                for line in ihf.read().splitlines():
                    if ': ' in line:
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            known_hashes.append(parts[1])

        try:
            pe = pefile.PE(file_path)
            file_hash = generate_import_hash(pe)
            for known_hash in known_hashes:
                similarity = calculate_similarity(file_hash, known_hash)
                if similarity >= 0.9:
                    print(f"Malicious File Detected - {file_path}")
                    match_found = True  # Set flag to true if a match is found
                    # Send alert message
                    send_alert_message(f'MALICIOUS ACTIVITY DETECTED - Cabin Crew VM detected malicious file: {file_path}')
                    break  # Stop checking further if a match is found
        except Exception as e:
            print(f"Error processing file '{file_path}': {e}")

    # If a malicious file is detected, delete it
    if match_found:
        try:
            os.remove(file_path)
            print(f"Malicious file {file_path} has been deleted.")
        except Exception as e:
            print(f"Failed to delete malicious file {file_path}: {e}")


import socket

def send_alert_message(message):
    # Corrected to use Comms VM's bridge network IP
    comms_vm_ip = '192.168.1.12'
    comms_vm_port = 5000
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((comms_vm_ip, comms_vm_port))
            sock.sendall(message.encode())
            print("Alert sent to Comms VM.")
    except Exception as e:
        print(f"Failed to send alert: {e}")



if __name__ == "__main__":
    scan_paths = ['/home/cabincrewnetwork/Pictures', '/home/cabincrewnetwork/Downloads','/home/cabincrewnetwork/Videos']  # List of paths to scan
    rules_output_folder = '/home/cabincrewnetwork/Desktop/MALWARE_RULE_GENERATION/MALWARE_RULES'
    import_hashes_output_folder = '/home/cabincrewnetwork/Desktop/MALWARE_RULE_GENERATION/IMPORT_HASHING'

    # Generate ngram index for all paths
    ngram_index = generate_ngram_index(scan_paths, rules_output_folder)

    print("Starting the script...")

    # Scan each directory in the list with YARA rules and import hashes
    scan_directory_with_yara_and_hashes(scan_paths, rules_output_folder, import_hashes_output_folder, ngram_index)

    print("Script execution finished.")







