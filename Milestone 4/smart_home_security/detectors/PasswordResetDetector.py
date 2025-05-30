from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

class PasswordResetDetector:
    def __init__(self, threshold: int = 3, time_window: int = 5):
        """
        Initialize detector with:
        - threshold: max allowed reset attempts (default 3)
        - time_window: minutes for counting attempts (default 5)
        """
        self.threshold = threshold
        self.time_window = timedelta(minutes=time_window)
        self.reset_attempts: Dict[str, List[datetime]] = {}
    
    def detect(self, user_id: str, timestamp: datetime) -> tuple[bool, Optional[str]]:
        """Detect frequent password reset attempts"""
        if user_id not in self.reset_attempts:
            self.reset_attempts[user_id] = []
        
        # Add current attempt
        self.reset_attempts[user_id].append(timestamp)
        
        # Filter attempts within time window
        recent_attempts = [
            attempt for attempt in self.reset_attempts[user_id]
            if timestamp - attempt <= self.time_window
        ]
        self.reset_attempts[user_id] = recent_attempts
        
        # Check if threshold exceeded
        if len(recent_attempts) > self.threshold:
            return True, (
                f"User {user_id} made {len(recent_attempts)} password reset attempts "
                f"in the last {self.time_window.seconds//60} minutes"
            )
        
        return False, None
    
    def get_event_data(self, user_id: str, timestamp: str, message: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event": "password_reset_anomaly",
            "user_id": user_id,
            "attempt_count": len(self.reset_attempts.get(user_id, [])),
            "time_window_minutes": self.time_window.seconds // 60,
            "message": message
        }