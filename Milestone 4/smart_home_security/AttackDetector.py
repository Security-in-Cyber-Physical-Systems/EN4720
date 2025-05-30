from datetime import datetime
from typing import Dict, Any

from smart_home_security.detectors.PowerAnomalyDetector import PowerAnomalyDetector
from smart_home_security.EventLogger import EventLogger

class AttackDetector:
    def __init__(self):
        self.logger = EventLogger()
        
        # Initialize all detectors
        self.power_anomaly_detector = PowerAnomalyDetector()
    
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
        
        return attack_detected