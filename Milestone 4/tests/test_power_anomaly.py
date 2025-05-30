import unittest
from datetime import datetime, timedelta
from smart_home_security.detectors import PowerAnomalyDetector
from smart_home_security import AttackDetector

#unit tests for PowerAnomalyDetector
class TestPowerAnomalyDetector(unittest.TestCase):    
    def setUp(self):
        self.detector = PowerAnomalyDetector(spike_threshold=1.5)
    
    def test_normal_power_readings(self):
        for i in range(10):
            self.detector.detect("device1", 100.0)
        
        is_anomaly, _ = self.detector.detect("device1", 120.0)
        self.assertFalse(is_anomaly)
    
    def test_power_spike_detection(self):
        for i in range(10):
            self.detector.detect("device1", 100.0)
        
        is_anomaly, msg = self.detector.detect("device1", 200.0)
        self.assertTrue(is_anomaly)
        self.assertIn("spike", msg.lower())
    
    def test_negative_value_detection(self):
        is_anomaly, msg = self.detector.detect("device1", -5.0)
        self.assertTrue(is_anomaly)
        self.assertIn("negative", msg.lower())

#integration tests for PowerAnomalyDetector with AttackDetector
class TestPowerIntegration(unittest.TestCase):    
    def setUp(self):
        self.detector = AttackDetector()
        self.now = datetime.now()
        
        # Create baseline readings
        for i in range(10):
            self.detector.instrument(
                "power_reading",
                "SYSTEM",
                "sensor1",
                "sensor1",
                self.now + timedelta(minutes=i),
                {"value": 100.0}
            )
    
    def test_normal_power_reading(self):
        result = self.detector.instrument(
            "power_reading",
            "SYSTEM",
            "sensor1",
            "sensor1",
            self.now + timedelta(minutes=11),
            {"value": 120.0}
        )
        self.assertFalse(result)
    
    def test_detected_power_spike(self):
        result = self.detector.instrument(
            "power_reading",
            "SYSTEM",
            "sensor1",
            "sensor1",
            self.now + timedelta(minutes=12),
            {"value": 200.0}
        )
        self.assertTrue(result)
    
    def test_detected_negative_value(self):
        result = self.detector.instrument(
            "power_reading",
            "SYSTEM",
            "sensor1",
            "sensor1",
            self.now + timedelta(minutes=13),
            {"value": -5.0}
        )
        self.assertTrue(result)