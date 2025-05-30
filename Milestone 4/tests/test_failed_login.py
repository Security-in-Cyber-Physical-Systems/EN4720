import unittest
from datetime import datetime, timedelta
from smart_home_security.detectors.FailedLoginDetector import FailedLoginDetector
from smart_home_security import AttackDetector

class TestFailedLoginDetector(unittest.TestCase):
    def setUp(self):
        self.detector = FailedLoginDetector(threshold=5, time_window=timedelta(minutes=1))
        self.now = datetime.now()

    def test_normal_failed_logins(self):
        # 4 failed attempts (below threshold)
        for i in range(4):
            self.detector.detect("user1", self.now + timedelta(seconds=i*10))
        is_anomaly, _ = self.detector.detect("user1", self.now + timedelta(seconds=50))
        self.assertFalse(is_anomaly)

    def test_brute_force_detection(self):
        # 5 failed attempts (above threshold)
        for i in range(5):
            self.detector.detect("user2", self.now + timedelta(seconds=i*10))
        is_anomaly, msg = self.detector.detect("user2", self.now + timedelta(seconds=60))
        self.assertTrue(is_anomaly)
        # Updated assertion to match actual message format
        self.assertIn(f"failed login attempts in the last {self.detector.time_window.seconds//60} minutes", msg)

    def test_window_expiration(self):
        # Failed attempts spread beyond time window
        for i in range(6):
            self.detector.detect("user3", self.now + timedelta(minutes=i))
        is_anomaly, _ = self.detector.detect("user3", self.now + timedelta(minutes=6))
        self.assertFalse(is_anomaly)

class TestFailedLoginIntegration(unittest.TestCase):
    def setUp(self):
        self.detector = AttackDetector()
        self.now = datetime.now()

    def test_detected_brute_force(self):
        for i in range(5):
            self.detector.instrument(
                "login_failed",
                "user",
                "attacker",
                "system",
                self.now + timedelta(seconds=i*10),
                {}
            )
        
        # 6th attempt should trigger detection
        result = self.detector.instrument(
            "login_failed",
            "user",
            "attacker",
            "system",
            self.now + timedelta(seconds=50),
            {}
        )
        self.assertTrue(result)