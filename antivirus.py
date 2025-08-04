#!/usr/bin/env python3

import os
import sys
import hashlib
import re
import threading
import queue
import time
import datetime
import json
import argparse
import magic
import psutil
from tqdm import tqdm

class SimpleAntivirus:
    def __init__(self):
        self.version = "1.0.0"
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.signature_db_path = os.path.expanduser("~/.simple_antivirus/signatures.json")
        self.signature_db = self.load_signatures()
        self.heuristic_patterns = [
            # Common malicious patterns
            rb"(?i)eval\s*\(\s*base64_decode",  # PHP shell pattern
            rb"(?i)exec\s*\(\s*\$_[A-Z]+",      # Command execution via GET/POST
            rb"(?i)system\s*\(\s*\$_[A-Z]+",    # Command execution via GET/POST
            rb"(?i)(rm|chmod|wget|curl)\s+",    # Common commands in shell scripts
            rb"(?i)\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", # Hex encoded shellcode
            rb"(?i)powershell -e",              # PowerShell encoded commands
            rb"(?i)meterpreter",                # Metasploit related
            rb"(?i)nc -e",                      # Netcat backdoor
            rb"(?i)/bin/bash -i",               # Reverse shell
            rb"(?i)python -c 'import socket,subprocess,os'" # Python reverse shell
        ]
        self.compiled_patterns = [re.compile(pattern) for pattern in self.heuristic_patterns]
        self.scan_queue = queue.Queue()
        self.scan_results = {
            "scanned_files": 0,
            "infected_files": 0,
            "suspicious_files": 0,
            "errors": 0,
            "detections": []
        }
        self.mime_filter = ["text/", "application/x-executable", "application/x-elf", 
                           "application/x-dosexec", "application/x-sharedlib",
                           "application/x-sh", "application/javascript", "application/x-python"]
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.signature_db_path), exist_ok=True)
        
    def load_signatures(self):
        """Load malware signatures from database file"""
        try:
            if os.path.exists(self.signature_db_path):
                with open(self.signature_db_path, 'r') as f:
                    return json.load(f)
            else:
                # Default signatures if none exist (example hashes of known malware)
                default_signatures = {
                    # Format: "hash": "malware_name"
                    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
                    "e4968ef99266df7c9a1f0637d2389dab": "Example Malware 1",
                    "b6e02c9dc24c5033a7d404a7d7e1d852": "Example Malware 2"
                }
                with open(self.signature_db_path, 'w') as f:
                    json.dump(default_signatures, f, indent=4)
                return default_signatures
        except Exception as e:
            print(f"Error loading signatures: {e}")
            return {}
            
    def update_signatures(self, new_signatures):
        """Add new signatures to the database"""
        try:
            self.signature_db.update(new_signatures)
            with open(self.signature_db_path, 'w') as f:
                json.dump(self.signature_db, f, indent=4)
            print(f"Signature database updated with {len(new_signatures)} new signatures")
        except Exception as e:
            print(f"Error updating signatures: {e}")
            
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
            return file_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None
            
    def scan_file_content(self, file_path):
        """Scan file content for suspicious patterns using heuristics"""
        try:
            suspicious_patterns = []
            
            # Check file size first to avoid reading large files
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                return suspicious_patterns
                
            # Get file MIME type
            mime_type = magic.from_file(file_path, mime=True)
            
            # Only scan specific file types to avoid binary data
            should_scan = False
            for mime_prefix in self.mime_filter:
                if isinstance(mime_type, str) and mime_type.startswith(mime_prefix):
                    should_scan = True
                    break
            
            if not should_scan:
                return suspicious_patterns
                
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Check for suspicious patterns
            for i, pattern in enumerate(self.compiled_patterns):
                if pattern.search(content):
                    suspicious_patterns.append(self.heuristic_patterns[i].decode('utf-8', errors='ignore'))
                    
            return suspicious_patterns
        except Exception as e:
            print(f"Error scanning content of {file_path}: {e}")
            return []
            
    def scan_file(self, file_path):
        """Scan a single file for malware"""
        try:
            result = {
                "file_path": file_path,
                "status": "clean",
                "detection": None,
                "detection_type": None
            }
            
            # Skip symbolic links, device files, etc.
            if not os.path.isfile(file_path) or os.path.islink(file_path):
                return result
                
            # Get file hash
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                self.scan_results["errors"] += 1
                return result
                
            # Check against signature database
            if file_hash in self.signature_db:
                result["status"] = "infected"
                result["detection"] = self.signature_db[file_hash]
                result["detection_type"] = "signature"
                self.scan_results["infected_files"] += 1
                return result
                
            # Perform heuristic scanning
            suspicious_patterns = self.scan_file_content(file_path)
            if suspicious_patterns:
                result["status"] = "suspicious"
                result["detection"] = "Suspicious patterns: " + ", ".join(suspicious_patterns)
                result["detection_type"] = "heuristic"
                self.scan_results["suspicious_files"] += 1
                
            self.scan_results["scanned_files"] += 1
            return result
        except Exception as e:
            self.scan_results["errors"] += 1
            print(f"Error scanning {file_path}: {e}")
            return {
                "file_path": file_path,
                "status": "error",
                "detection": str(e),
                "detection_type": None
            }
            
    def worker(self):
        """Worker thread to process scan queue"""
        while True:
            try:
                file_path = self.scan_queue.get(timeout=1)
                result = self.scan_file(file_path)
                
                if result["status"] != "clean":
                    self.scan_results["detections"].append(result)
                    
                self.scan_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                print(f"Worker error: {e}")
                self.scan_queue.task_done()
                
    def scan_directory(self, directory_path, max_workers=4):
        """Scan all files in a directory recursively"""
        start_time = time.time()
        
        print(f"Starting scan of {directory_path}...")
        
        # First, count files to show progress
        total_files = 0
        for root, _, files in os.walk(directory_path):
            total_files += len(files)
            
        print(f"Found {total_files} files to scan")
        
        # Create a progress bar
        progress_bar = tqdm(total=total_files, unit="files")
        
        # Populate queue with files
        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.scan_queue.put(file_path)
                
        # Start worker threads
        threads = []
        for _ in range(min(max_workers, os.cpu_count() or 1)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Monitor progress
        while not self.scan_queue.empty():
            initial_size = self.scan_queue.qsize()
            time.sleep(0.5)
            processed = initial_size - self.scan_queue.qsize()
            progress_bar.update(processed)
            
        # Wait for all tasks to complete
        self.scan_queue.join()
        
        # Close progress bar
        progress_bar.close()
        
        # Wait for all threads to finish
        for t in threads:
            t.join()
            
        # Calculate scan time
        elapsed_time = time.time() - start_time
        
        # Add scan time to results
        self.scan_results["scan_time"] = f"{elapsed_time:.2f} seconds"
        
        return self.scan_results
        
    def scan_running_processes(self):
        """Scan running processes for suspicious activity"""
        print("Scanning running processes...")
        
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                # Get process info
                proc_info = proc.info
                
                # Skip processes with no executable path
                if not proc_info['exe']:
                    continue
                    
                # Check if the process executable exists
                if os.path.exists(proc_info['exe']):
                    # Scan the executable
                    result = self.scan_file(proc_info['exe'])
                    
                    if result["status"] != "clean":
                        suspicious_processes.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "path": proc_info['exe'],
                            "cmdline": " ".join(proc_info['cmdline']) if proc_info['cmdline'] else "",
                            "detection": result["detection"],
                            "detection_type": result["detection_type"]
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return suspicious_processes
        
    def generate_report(self, results, file_path=None):
        """Generate a detailed report of scan results"""
        report = {
            "scanner_version": self.version,
            "scan_date": self.scan_date,
            "results": results,
            "process_scan": self.scan_running_processes() if os.geteuid() == 0 else "Process scanning requires root privileges"
        }
        
        # Print summary to console
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Scanned files: {results['scanned_files']}")
        print(f"Infected files: {results['infected_files']}")
        print(f"Suspicious files: {results['suspicious_files']}")
        print(f"Errors encountered: {results['errors']}")
        print(f"Scan time: {results['scan_time']}")
        print("="*50)
        
        # Print detections
        if results['detections']:
            print("\nDETECTIONS:")
            for detection in results['detections']:
                status_color = "\033[91m" if detection['status'] == "infected" else "\033[93m"
                reset_color = "\033[0m"
                print(f"{status_color}{detection['status'].upper()}{reset_color}: {detection['file_path']}")
                print(f"  Detection: {detection['detection']}")
                print(f"  Type: {detection['detection_type']}")
                print("-"*50)
                
        # Save report to file if requested
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(report, f, indent=4)
                print(f"\nReport saved to {file_path}")
            except Exception as e:
                print(f"Error saving report: {e}")
                
        return report

def main():
    parser = argparse.ArgumentParser(description="Simple Python Antivirus for Linux")
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--report', help='Path to save the report (JSON format)')
    parser.add_argument('--threads', type=int, default=4, help='Number of scanner threads')
    args = parser.parse_args()
    
    scanner = SimpleAntivirus()
    
    if os.path.isfile(args.path):
        result = scanner.scan_file(args.path)
        scanner.scan_results["scanned_files"] = 1
        scanner.scan_results["scan_time"] = "< 1 second"
        if result["status"] != "clean":
            scanner.scan_results["detections"].append(result)
            if result["status"] == "infected":
                scanner.scan_results["infected_files"] = 1
            elif result["status"] == "suspicious":
                scanner.scan_results["suspicious_files"] = 1
    elif os.path.isdir(args.path):
        scanner.scan_directory(args.path, max_workers=args.threads)
    else:
        print(f"Error: {args.path} is not a valid file or directory")
        sys.exit(1)
        
    scanner.generate_report(scanner.scan_results, args.report)
    
if __name__ == "__main__":
    # Check if running as root for full functionality
    if os.geteuid() != 0:
        print("Warning: Running without root privileges. Some features will be limited.")
    main()
