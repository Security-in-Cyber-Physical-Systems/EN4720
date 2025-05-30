from typing import Dict, List, Optional, Any, Set
from datetime import datetime, time

class RoleAnomalyDetector:
    def __init__(self):
        """Initialize detector with business hours (9 AM to 6 PM)"""
        self.business_hours_start = time(9, 0)  # 9 AM
        self.business_hours_end = time(18, 0)   # 6 PM
        self.user_roles: Dict[str, Set[str]] = {}  # Tracks roles per user
    
    def is_business_hours(self, dt: datetime) -> bool:
        """Check if the given datetime is within business hours"""
        current_time = dt.time()
        return self.business_hours_start <= current_time <= self.business_hours_end
    
    def detect(self, user_id: str, role: str, timestamp: datetime) -> tuple[bool, Optional[str]]:
        """Detect if a user is logging in with multiple roles outside business hours"""
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        
        # Add current role to user's role set
        self.user_roles[user_id].add(role)
        
        # Only check for anomalies outside business hours
        if not self.is_business_hours(timestamp):
            # Check if user has multiple roles
            if len(self.user_roles[user_id]) > 1:
                roles_str = ", ".join(sorted(self.user_roles[user_id]))
                return True, (
                    f"User {user_id} logged in with multiple roles ({roles_str}) "
                    f"outside business hours (9 AM - 6 PM)"
                )
        
        # During business hours, reset the tracking for this user
        else:
            self.user_roles[user_id] = {role}
        
        return False, None
    
    def get_event_data(self, user_id: str, roles: List[str], timestamp: str, message: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event": "role_anomaly",
            "user_id": user_id,
            "roles": roles,
            "message": message,
            "is_business_hours": self.is_business_hours(datetime.fromisoformat(timestamp))
        }