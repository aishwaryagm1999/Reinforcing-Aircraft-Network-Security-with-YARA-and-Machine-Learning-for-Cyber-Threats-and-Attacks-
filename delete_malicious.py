import os

def delete_malicious_files(file_list_path="malicious_files.txt"):
    try:
        with open(file_list_path, "r") as f:
            lines = f.readlines()
        for line in lines:
            file_path = line.strip()
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted malicious file: {file_path}")
            else:
                print(f"File not found: {file_path}")
        # Clear the contents of the file list after deletion
        open(file_list_path, "w").close()
    except FileNotFoundError:
        print(f"No file list found at {file_list_path}.")

if __name__ == "__main__":
    delete_malicious_files()

