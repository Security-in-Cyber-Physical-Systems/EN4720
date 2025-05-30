from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any

class ToggleSpamDetector:
    def __init__(
        self, 
        threshold: int = 10, 
        time_window: timedelta = timedelta(seconds=30)
    ):
        """
        Detects rapid device toggling (e.g., on/off spam).
        
        Args:
            threshold: Max allowed toggles in time_window (default: 10)
            time_window: Rolling window for counting (default: 30 seconds)
        """
        self.threshold = threshold
        self.time_window = time_window
        self.command_history: Dict[str, List[datetime]] = {}  # {device_id: [timestamps]}

    def detect(self, device_id: str, timestamp: datetime) -> Tuple[bool, Optional[str]]:
        """Record a toggle command and check for spam"""
        if device_id not in self.command_history:
            self.command_history[device_id] = []

        # Add current command
        self.command_history[device_id].append(timestamp)

        # Purge old entries outside time window
        self.command_history[device_id] = [
            t for t in self.command_history[device_id]
            if timestamp - t <= self.time_window
        ]

        # Check threshold
        if len(self.command_history[device_id]) > self.threshold:
            return True, (
                f"Device {device_id} has {len(self.command_history[device_id])} "
                f"toggle commands in the last {self.time_window.total_seconds()} seconds"
            )
        return False, None

    def get_event_data(self, device_id: str, timestamp: str, message: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event": "toggle_spam",
            "device_id": device_id,
            "count": len(self.command_history.get(device_id, [])),
            "time_window_seconds": self.time_window.total_seconds(),
            "message": message
        }