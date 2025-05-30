import unittest
from datetime import datetime, timedelta
from smart_home_security.detectors.PasswordResetDetector import PasswordResetDetector
from smart_home_security import AttackDetector

class TestPasswordResetDetector(unittest.TestCase):    
    def setUp(self):
        self.detector = PasswordResetDetector(threshold=3, time_window=5)
        self.now = datetime.now()
    
    def test_normal_reset_behavior(self):
        # Within threshold
        for i in range(3):
            is_anomaly, _ = self.detector.detect("user1", self.now + timedelta(minutes=i))
            self.assertFalse(is_anomaly)
    
    def test_frequent_reset_detection(self):
        # Exceed threshold
        for i in range(3):
            self.detector.detect("user2", self.now + timedelta(minutes=i))
        
        is_anomaly, msg = self.detector.detect("user2", self.now + timedelta(minutes=3.5))
        self.assertTrue(is_anomaly)
        self.assertIn("password reset attempts", msg.lower())
    
    def test_reset_window_expiry(self):
        # Attempts spread beyond time window
        for i in range(4):
            self.detector.detect("user3", self.now + timedelta(minutes=i*6))  # 6 min apart
        
        is_anomaly, _ = self.detector.detect("user3", self.now + timedelta(minutes=24))
        self.assertFalse(is_anomaly)

class TestPasswordResetIntegration(unittest.TestCase):    
    def setUp(self):
        self.detector = AttackDetector()
        self.now = datetime.now()
    
    def test_normal_reset_behavior(self):
        for i in range(3):
            result = self.detector.instrument(
                "password_reset",
                "user",
                "user4",
                "system",
                self.now + timedelta(minutes=i),
                {}
            )
            self.assertFalse(result)
    
    def test_detected_frequent_resets(self):
        for i in range(3):
            self.detector.instrument(
                "password_reset",
                "user",
                "user5",
                "system",
                self.now + timedelta(minutes=i),
                {}
            )
        
        result = self.detector.instrument(
            "password_reset",
            "user",
            "user5",
            "system",
            self.now + timedelta(minutes=3.5),
            {}
        )
        self.assertTrue(result)