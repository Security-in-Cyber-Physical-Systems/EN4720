from datetime import datetime
from typing import Dict, Any, Set

from smart_home_security.detectors.PowerAnomalyDetector import PowerAnomalyDetector
from smart_home_security.detectors.UnauthorizedAccessDetector import UnauthorizedAccessDetector
from smart_home_security.detectors.RoleAnomalyDetector import RoleAnomalyDetector
from smart_home_security.detectors.PasswordResetDetector import PasswordResetDetector
from smart_home_security.detectors.GeoAnomalyDetector import GeoAnomalyDetector
from smart_home_security.detectors.FailedLoginDetector import FailedLoginDetector
from smart_home_security.EventLogger import EventLogger

class AttackDetector:
    def __init__(self):
        self.logger = EventLogger()
        
        # Initialize all detectors
        self.power_anomaly_detector = PowerAnomalyDetector()
        self.unauthorized_access_detector = UnauthorizedAccessDetector()
        self.role_anomaly_detector = RoleAnomalyDetector()
        self.password_reset_detector = PasswordResetDetector()
        self.failed_login_detector = FailedLoginDetector()
        self.geo_anomaly_detector = GeoAnomalyDetector(
            blacklist_countries={'KP', 'SY', 'IR', 'CU'},
            tor_exit_nodes=self._load_tor_exit_nodes()
        )
    
    def _load_tor_exit_nodes(self) -> Set[str]:
        """Load known TOR exit nodes (simplified example)"""
        # In production, you would fetch this from:
        # https://check.torproject.org/torbulkexitlist
        return {
            '51.15.125.1',
            '62.210.254.133',
            '185.220.101.204'
        }

    
    def instrument(self, event_name: str, user_role: str, user_id: str, 
                  source_id: str, timestamp: datetime, context: Dict[str, Any]) -> bool:
   
        attack_detected = False
        
        if event_name == "power_reading":
            if "value" in context:
                is_anomaly, message = self.power_anomaly_detector.detect(
                    source_id, context["value"]
                )
                if is_anomaly:
                    event_data = self.power_anomaly_detector.get_event_data(
                        source_id, context["value"], timestamp.isoformat(), message
                    )
                    self.logger.log_event(event_data)
                    attack_detected = True
        
        if event_name == "user_login":
            # Check for geo anomalies if IP is provided
            if "ip_address" in context:
                is_anomaly, message = self.geo_anomaly_detector.detect(
                    user_id, context["ip_address"], timestamp
                )
                if is_anomaly:
                    event_data = self.geo_anomaly_detector.get_event_data(
                        user_id, context["ip_address"], timestamp.isoformat(), message
                    )
                    self.logger.log_event(event_data)
                    attack_detected = True
            
            # Check for role anomalies
            is_anomaly, message = self.role_anomaly_detector.detect(
                user_id, user_role, timestamp
            )
            if is_anomaly:
                roles = list(self.role_anomaly_detector.user_roles[user_id])
                event_data = self.role_anomaly_detector.get_event_data(
                    user_id, roles, timestamp.isoformat(), message
                )
                self.logger.log_event(event_data)
                attack_detected = True

        if event_name == "password_reset":
            is_anomaly, message = self.password_reset_detector.detect(
                user_id, timestamp
            )
            if is_anomaly:
                event_data = self.password_reset_detector.get_event_data(
                    user_id, timestamp.isoformat(), message
                )
                self.logger.log_event(event_data)
                attack_detected = True
        
        if event_name == "login_failed":
            is_anomaly, message = self.failed_login_detector.detect(
                user_id, timestamp
            )
            if is_anomaly:
                event_data = self.failed_login_detector.get_event_data(
                    user_id, timestamp.isoformat(), message
                )
                self.logger.log_event(event_data)
                attack_detected = True

        if "allowed_roles" in context:
            if self.unauthorized_access_detector.detect(user_role, context["allowed_roles"]):
                event_data = self.unauthorized_access_detector.get_event_data(
                    user_role,
                    context["allowed_roles"],
                    timestamp.isoformat(),
                    user_id,
                    source_id
                )
                self.logger.log_event(event_data)
                attack_detected = True
        
        return attack_detected