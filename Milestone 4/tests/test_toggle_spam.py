import unittest
from datetime import datetime, timedelta
from smart_home_security.detectors.ToggleSpamDetector import ToggleSpamDetector
from smart_home_security import AttackDetector

class TestToggleSpamDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ToggleSpamDetector(threshold=10, time_window=timedelta(seconds=30))
        self.now = datetime.now()

    def test_normal_usage(self):
        # 9 toggles in 30s (below threshold)
        for i in range(9):
            self.detector.detect("light1", self.now + timedelta(seconds=i))
        is_anomaly, _ = self.detector.detect("light1", self.now + timedelta(seconds=29))
        self.assertFalse(is_anomaly)

    def test_toggle_spam_detection(self):
        # 11 toggles in 20s (exceeds threshold)
        for i in range(11):
            self.detector.detect("light2", self.now + timedelta(seconds=i*2))
        is_anomaly, msg = self.detector.detect("light2", self.now + timedelta(seconds=20))
        self.assertTrue(is_anomaly)
        self.assertIn("toggle commands", msg)

    def test_window_reset(self):
        # 10 fast toggles + 1 after window expires
        for i in range(10):
            self.detector.detect("light3", self.now + timedelta(seconds=i))
        # Wait 31 seconds (outside window)
        is_anomaly, _ = self.detector.detect(
            "light3", 
            self.now + timedelta(seconds=31)
        )
        self.assertFalse(is_anomaly)

class TestToggleSpamIntegration(unittest.TestCase):
    def setUp(self):
        self.detector = AttackDetector()
        self.now = datetime.now()

    def test_detected_toggle_spam(self):
        # Send 11 toggle commands in 20 seconds
        for i in range(11):
            result = self.detector.instrument(
                "device_toggle",
                "user",
                "attacker",
                "smart_switch",
                self.now + timedelta(seconds=i*2),
                {"device_id": "light1"}
            )
            # Only check last result (should trigger)
            if i == 10:
                self.assertTrue(result)
            else:
                self.assertFalse(result)