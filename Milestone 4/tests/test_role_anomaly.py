import unittest
from datetime import datetime, time, timedelta
from smart_home_security.detectors.RoleAnomalyDetector import RoleAnomalyDetector
from smart_home_security import AttackDetector

class TestRoleAnomalyDetector(unittest.TestCase):    
    def setUp(self):
        self.detector = RoleAnomalyDetector()
        self.business_hour = datetime(2023, 1, 1, 10, 0)  # 10 AM
        self.after_hours = datetime(2023, 1, 1, 20, 0)    # 8 PM
    
    def test_normal_business_hours_usage(self):
        # Multiple roles during business hours - no anomaly
        is_anomaly, _ = self.detector.detect("user1", "admin", self.business_hour)
        self.assertFalse(is_anomaly)
        
        is_anomaly, _ = self.detector.detect("user1", "manager", self.business_hour + timedelta(hours=1))
        self.assertFalse(is_anomaly)
    
    def test_after_hours_anomaly(self):
        # Multiple roles after business hours - anomaly
        is_anomaly, _ = self.detector.detect("user2", "admin", self.after_hours)
        self.assertFalse(is_anomaly)  # First login is fine
        
        is_anomaly, msg = self.detector.detect("user2", "guest", self.after_hours + timedelta(hours=1))
        self.assertTrue(is_anomaly)
        self.assertIn("outside business hours", msg.lower())
    
    def test_single_role_after_hours(self):
        # Single role after business hours - no anomaly
        is_anomaly, _ = self.detector.detect("user3", "admin", self.after_hours)
        self.assertFalse(is_anomaly)
        
        is_anomaly, _ = self.detector.detect("user3", "admin", self.after_hours + timedelta(hours=1))
        self.assertFalse(is_anomaly)

class TestRoleIntegration(unittest.TestCase):    
    def setUp(self):
        self.detector = AttackDetector()
        self.business_hour = datetime(2023, 1, 1, 10, 0)  # 10 AM
        self.after_hours = datetime(2023, 1, 1, 20, 0)    # 8 PM
    
    def test_normal_business_hours_usage(self):
        result = self.detector.instrument(
            "user_login",
            "admin",
            "user1",
            "system",
            self.business_hour,
            {}
        )
        self.assertFalse(result)
        
        result = self.detector.instrument(
            "user_login",
            "manager",
            "user1",
            "system",
            self.business_hour + timedelta(hours=1),
            {}
        )
        self.assertFalse(result)
    
    def test_detected_after_hours_anomaly(self):
        result = self.detector.instrument(
            "user_login",
            "admin",
            "user2",
            "system",
            self.after_hours,
            {}
        )
        self.assertFalse(result)
        
        result = self.detector.instrument(
            "user_login",
            "guest",
            "user2",
            "system",
            self.after_hours + timedelta(hours=1),
            {}
        )
        self.assertTrue(result)