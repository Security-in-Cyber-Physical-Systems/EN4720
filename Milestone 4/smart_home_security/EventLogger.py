import json
from datetime import datetime
from typing import Dict, Any

class EventLogger:
    def __init__(self, log_file: str = "logs.json"):
        self.log_file = log_file
    
    def log_event(self, event_data: Dict[str, Any]):
        """Log suspicious events to a JSON file"""
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event_data) + '\n')