from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta

class FailedLoginDetector:
    def __init__(self, threshold: int = 5, time_window: timedelta = timedelta(minutes=1)):
        """
        Initialize detector with:
        - threshold: max allowed failed attempts (default 5)
        - time_window: time period for counting attempts (default 1 minute)
        """
        self.threshold = threshold
        self.time_window = time_window
        self.failed_attempts: Dict[str, List[datetime]] = {}

    def detect(self, username: str, timestamp: datetime) -> Tuple[bool, Optional[str]]:
        """Record a failed login attempt and check if threshold is exceeded"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []

        # Add current attempt
        self.failed_attempts[username].append(timestamp)

        # Remove attempts outside the time window
        self.failed_attempts[username] = [
            attempt for attempt in self.failed_attempts[username]
            if timestamp - attempt <= self.time_window
        ]

        # Check if threshold exceeded
        if len(self.failed_attempts[username]) > self.threshold:
            return True, (
                f"User {username} has {len(self.failed_attempts[username])} "
                f"failed login attempts in the last {self.time_window.seconds//60} minutes"
            )

        return False, None

    def get_event_data(self, username: str, timestamp: str, message: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event": "failed_login_anomaly",
            "user_id": username,
            "attempt_count": len(self.failed_attempts.get(username, [])),
            "time_window_minutes": self.time_window.seconds // 60,
            "message": message
        }