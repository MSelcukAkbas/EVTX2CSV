import os
import json
import tempfile
import subprocess
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class EVTXToCSVConverter:
    """ 
    A class to convert EVTX files to CSV format.

    This class reads a JSON file containing event log file names and converts them to CSV files.
    """

    def __init__(self, json_file_path: str = "evtx_path.json"):
        """ 
        Initializes the converter with the specified JSON file path.

        Example JSON format:
        {
            "event_logs": [
                {
                    "file_name": "Application.evtx" ,
                    "description": "Contains event logs related to the application."
                },
                {
                    "file_name": "HardwareEvents.evtx" ,
                    "description": "Contains event logs related to hardware."
                }
            ]
        }   
        
        Args:
            json_file_path (str): The path to the JSON file containing event log filenames.
        """
        self.json_file_path = json_file_path
        self.valid_file_paths = []
        self.output_directory = os.path.join(os.getcwd(), "evtx_csv")
        self.error_log_file = os.path.join(os.getcwd(), "log_error.csv")
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self.load_event_log_filenames()
        batch_commands = self.generate_batch_commands()
        if batch_commands:
            self.create_batch_file(batch_commands)
            self.execute_batch_file_as_admin()
        else: 
            self.log_error("Initialization", "Batch command generation failed.")

    def log_error(self, function_name, error):
        """ 
        Logs the error information to a CSV file and prints to the terminal.
        
        Args:
            function_name (str): The name of the function where the error occurred.
            error (Exception): The error that occurred.
        """
        with open(self.error_log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            if f.tell() == 0:
                writer.writerow(['Timestamp', 'Error Type', 'Error Message', 'Function Name'])
            writer.writerow([self.timestamp, type(error).__name__, str(error), function_name])
        
        os.system(f'echo [ERROR] {self.timestamp}: {error} in {function_name}. See log for details.')

    def load_event_log_filenames(self):
        """ 
        Reads the main JSON file to get event log file names and verifies them.
        """
        try:
            with open(self.json_file_path, "r", encoding="utf-8") as json_file:
                data = json.load(json_file).get('evtx_path', [])
                if not data:
                    raise ValueError("No 'evtx_path' key found in the JSON file or it is empty.")
                self.verify_event_log_files(data)
        except FileNotFoundError as e:
            self.log_error("load_event_log_filenames", e)
            raise SystemExit("JSON file not found. Please check the file path.")
        except json.JSONDecodeError as e:
            self.log_error("load_event_log_filenames", e)
            raise SystemExit("Error reading the JSON file. Please check the file format.")
        except Exception as e:
            self.log_error("load_event_log_filenames", e)

    def verify_event_log_files(self, event_log_file_names):
        """ 
        Verifies the existence of event log files in the specified directory.
        
        Args:
            event_log_file_names (list): List of event log file names to verify.
        """
        main_directory = "C:/Windows/System32/winevt/Logs/"
        with ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(os.path.isfile, os.path.join(main_directory, item['file_name'])): item['file_name']
                for item in event_log_file_names
            }
            for future in as_completed(futures):
                file_name = futures[future]
                if future.result():
                    self.valid_file_paths.append(os.path.join(main_directory, file_name))
                else:
                    os.system(f'echo [WARNING] File not found: {file_name}')

        if not self.valid_file_paths:
            raise FileNotFoundError("No valid files found.")

    def generate_batch_commands(self):
        """ 
        Creates batch commands to convert EVTX files to CSV.
        
        Returns:
            str: The batch commands to execute.
        """
        os.makedirs(self.output_directory, exist_ok=True)
        batch_commands = []

        for path in self.valid_file_paths:
            output_file_name = os.path.basename(path).replace(".evtx", ".csv")
            full_output_path = os.path.join(self.output_directory, output_file_name)
            batch_commands.append(f'powershell -Command "Get-WinEvent -Path \'{path}\' | Export-CSV \'{full_output_path}\'"')

        return "@echo off\n" + "\n".join(batch_commands) if batch_commands else None

    def create_batch_file(self, batch_text: str):
        """ 
        Creates a temporary batch file to execute the conversion.
        
        Args:
            batch_text (str): The batch file text to write.
        """
        try:
            with tempfile.NamedTemporaryFile(suffix=".bat", delete=False) as batch_file:
                batch_file.write(batch_text.encode('utf-8'))
                self.batch_file_path = batch_file.name
        except Exception as e:
            self.log_error("create_batch_file", e)

    def execute_batch_file_as_admin(self):
        """ 
        Executes the batch file as an administrator.
        """
        try:
            subprocess.run(['powershell', '-Command', f'Start-Process -File "{self.batch_file_path}" -Verb RunAs'], check=True)
        except subprocess.CalledProcessError as e:
            self.log_error("execute_batch_file_as_admin", e)
            os.system("[ERROR] Failed to run as admin.")

if __name__ == "__main__":
    EVTXToCSVConverter()
