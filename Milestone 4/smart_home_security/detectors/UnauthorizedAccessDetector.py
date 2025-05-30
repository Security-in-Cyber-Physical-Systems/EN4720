from typing import List

class UnauthorizedAccessDetector:

    def detect(self, user_role: str, allowed_roles: List[str]) -> bool:
        return user_role not in allowed_roles

    def get_event_data(self, user_role: str, allowed_roles: List[str], 
                      timestamp: str, user_id: str, source_id: str) -> dict:

        return {
            "timestamp": timestamp,
            "event": "unauthorized_access_attempt",
            "user_id": user_id,
            "user_role": user_role,
            "source_id": source_id,
            "allowed_roles": allowed_roles,
            "message": f"User {user_id} with role {user_role} attempted unauthorized action"
        }