from typing import Dict, List, Optional, Any

class PowerAnomalyDetector:
    def __init__(self, spike_threshold: float = 1.5):
        self.spike_threshold = spike_threshold  # 150% of average
        self.power_readings: Dict[str, List[float]] = {}
        self.power_averages: Dict[str, float] = {}
    
    def detect(self, device_id: str, value: float) -> tuple[bool, Optional[str]]:
        """Detect abnormal power consumption"""
        if device_id not in self.power_readings:
            self.power_readings[device_id] = []
        
        self.power_readings[device_id].append(value)
        
        # Update average if we have enough data (minimum 10 readings)
        if len(self.power_readings[device_id]) >= 10:
            self.power_averages[device_id] = (
                sum(self.power_readings[device_id]) / len(self.power_readings[device_id])
            )
        
        # Check for anomalies
        if value <= 0:
            return True, f"Negative/zero power reading for device {device_id}"
        elif device_id in self.power_averages and value > self.power_averages[device_id] * self.spike_threshold:
            return True, (
                f"Power spike detected for device {device_id} "
                f"(value: {value}, avg: {self.power_averages[device_id]:.2f})"
            )
        
        return False, None
    
    def get_event_data(self, device_id: str, value: float, timestamp: str, message: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event": "power_anomaly",
            "device_id": device_id,
            "value": value,
            "average": self.power_averages.get(device_id, None),
            "message": message
        }