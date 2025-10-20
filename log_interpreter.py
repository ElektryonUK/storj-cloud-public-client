import os
import time
import json
import re
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load global configuration from environment variables
DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL')
LOG_POLL_INTERVAL = int(os.getenv('LOG_POLL_INTERVAL', 60)) # seconds
BATCH_SIZE = 50
CONFIG_FILE_PATH = 'config.json'

# --- Log Parsing Logic ---

# Pre-compile regex for performance. This captures the main parts of a log line.
LOG_LINE_REGEX = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+'
    r'(?P<level>INFO|ERROR|WARN|DEBUG|FATAL)\s+'
    r'(?P<subsystem>[\w:-]+)\s+'
    r'(?P<message>.*?)\s*'
    r'(?P<json_data>{.*})?$'
)

# Simplified mapping for demonstration. A real implementation would have all 40 templates.
LOG_TEMPLATES = {
    'piecestore.download.failed': 'audit_failure',
    'contact.ping.failed': 'contact_failure',
    'piecestore.upload.finished': 'upload_success',
    'piecestore.download.success': 'download_success' # For heatmap IP
}

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parses a single log line and structures it."""
    match = LOG_LINE_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    json_data = {}
    if data['json_data']:
        try:
            json_data = json.loads(data['json_data'])
        except json.JSONDecodeError:
            pass # Ignore malformed JSON

    # Determine event type from message content for simplicity
    event_type = "unknown"
    for keyword, event in LOG_TEMPLATES.items():
        if keyword in data['message'] or keyword in data['subsystem']:
            event_type = event
            break
            
    # Extract remote IP for heatmap data if available (e.g., from an httpserver request)
    remote_ip = json_data.get('remote_addr')
    # This is a simplification; in a real scenario you'd parse different fields
    if not remote_ip and 'Action' in json_data and json_data.get('Action') == 'GET':
        # Placeholder for extracting IP from other log types if possible
        pass

    return {
        'timestamp': data['timestamp'],
        'event_type': event_type,
        'severity': data['level'].lower(),
        'message': data['message'],
        'details': json_data,
        'remote_ip': remote_ip,
    }


# --- Main Application Logic ---

def load_node_config() -> List[Dict[str, str]]:
    """Loads node configurations from the JSON file."""
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.error(f"Error reading or parsing '{CONFIG_FILE_PATH}'. Please ensure it exists and is valid.")
        return []

def follow_log_file(filepath: str):
    """Yields new lines from a file as they are added."""
    try:
        with open(filepath, 'r') as file:
            # Go to the end of the file
            file.seek(0, 2)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except FileNotFoundError:
        logging.error(f"Log file not found at {filepath}. Please check the path.")
        return


def send_logs_to_dashboard(node_auth_token: str, logs: List[Dict[str, Any]]):
    """Sends a batch of parsed logs to the dashboard API."""
    if not DASHBOARD_API_URL:
        logging.error("DASHBOARD_API_URL is not set. Cannot send logs.")
        return

    try:
        headers = {
            'Content-Type': 'application/json',
            'X-Node-Auth-Token': node_auth_token
        }
        response = requests.post(f"{DASHBOARD_API_URL}/data/logs", headers=headers, json=logs)
        response.raise_for_status()
        logging.info(f"Successfully sent {len(logs)} log entries.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send logs to dashboard: {e}")

def main():
    """
    Main function to configure and run the log interpreter for multiple nodes.
    """
    if not DASHBOARD_API_URL:
        logging.critical("DASHBOARD_API_URL environment variable not set. Exiting.")
        return

    nodes = load_node_config()
    if not nodes:
        logging.critical("No nodes configured in 'config.json'. Exiting.")
        return
        
    logging.info(f"Starting log interpreter for {len(nodes)} node(s).")
    
    # We need to create a separate process or thread for each log file
    # For simplicity here, we'll just process the first configured node.
    # A production version would use multiprocessing.
    if len(nodes) > 1:
        logging.warning("This version only processes the first node in config.json. Multi-node processing requires threading.")

    first_node = nodes[0]
    log_file_path = first_node.get('logFilePath')
    auth_token = first_node.get('authToken')

    if not log_file_path or not auth_token:
        logging.critical("The first node in config.json is missing 'logFilePath' or 'authToken'. Exiting.")
        return

    log_batch = []
    last_send_time = time.time()

    for line in follow_log_file(log_file_path):
        parsed_log = parse_log_line(line)
        if parsed_log:
            log_batch.append(parsed_log)
        
        current_time = time.time()
        
        # Send batch if it's full or if the poll interval has passed
        if len(log_batch) >= BATCH_SIZE or (current_time - last_send_time) >= LOG_POLL_INTERVAL:
            if log_batch:
                send_logs_to_dashboard(auth_token, log_batch)
                log_batch = []
                last_send_time = current_time


if __name__ == "__main__":
    main()

