import unittest
from datetime import datetime, timedelta
from smart_home_security.detectors.GeoAnomalyDetector import GeoAnomalyDetector
from smart_home_security import AttackDetector

class TestGeoAnomalyDetector(unittest.TestCase):    
    def setUp(self):
        # Setup mock locations for testing
        self.mock_locations = {
            '1.2.3.4': (0.0, 0.0, 'US'),  # TOR exit node
            '5.6.7.8': (0.0, 0.0, 'KP'),  # Blacklisted country (North Korea)
            '9.10.11.12': (35.7, 139.7, 'JP'),  # Tokyo
            '13.14.15.16': (48.9, 2.4, 'FR'),   # Paris
            '8.8.8.8': (37.5, -122.3, 'US')     # Normal IP
        }
        
        self.detector = GeoAnomalyDetector(
            max_speed_kmh=900,
            blacklist_countries={'KP', 'SY', 'IR', 'CU'},  # Match AttackDetector config
            tor_exit_nodes={'1.2.3.4'},  # Test TOR node
            mock_locations=self.mock_locations
        )
        self.now = datetime.now()
    
    def test_tor_exit_node_detection(self):
        is_anomaly, msg = self.detector.detect("user1", "1.2.3.4", self.now)
        self.assertTrue(is_anomaly)
        self.assertIn("TOR exit node", msg)
    
    def test_blacklisted_country(self):
        is_anomaly, msg = self.detector.detect("user2", "5.6.7.8", self.now)
        self.assertTrue(is_anomaly)
        self.assertIn("blacklisted country KP", msg)
    
    def test_impossible_travel(self):
        # First login in New York (~40.7, -74.0)
        self.detector.user_locations["user3"] = [
            (self.now - timedelta(minutes=10), 40.7, -74.0)
        ]
        # Then login in Tokyo (~35.7, 139.7) 10 minutes later
        is_anomaly, msg = self.detector.detect("user3", "9.10.11.12", self.now)
        self.assertTrue(is_anomaly)
        self.assertIn("Impossible travel", msg)
        self.assertIn("speed", msg)
    
    def test_normal_travel(self):
        # First login in London (~51.5, -0.1)
        self.detector.user_locations["user4"] = [
            (self.now - timedelta(hours=2), 51.5, -0.1)
        ]
        # Then login in Paris (~48.9, 2.4) 2 hours later
        is_anomaly, _ = self.detector.detect("user4", "13.14.15.16", self.now)
        self.assertFalse(is_anomaly)
    
    def test_normal_access(self):
        is_anomaly, _ = self.detector.detect("user5", "8.8.8.8", self.now)
        self.assertFalse(is_anomaly)

class TestGeoIntegration(unittest.TestCase):    
    def setUp(self):
        self.detector = AttackDetector()
        # Add our test IPs to the detector's sets
        self.detector.geo_anomaly_detector.tor_exit_nodes.add('1.2.3.4')
        # Setup mock locations for integration testing
        self.detector.geo_anomaly_detector.mock_locations = {
            '1.2.3.4': (0.0, 0.0, 'US'),
            '5.6.7.8': (0.0, 0.0, 'KP'),
            '8.8.8.8': (37.5, -122.3, 'US'),
            '9.10.11.12': (35.7, 139.7, 'JP'),  # Tokyo
            '13.14.15.16': (40.7, -74.0, 'US')  # New York
        }
        self.now = datetime.now()
    
    def test_detected_tor_access(self):
        result = self.detector.instrument(
            "user_login",
            "user",
            "user123",
            "system",
            self.now,
            {"ip_address": "1.2.3.4"}
        )
        self.assertTrue(result, "Should detect TOR exit node")
    
    def test_detected_blacklisted_country(self):
        result = self.detector.instrument(
            "user_login",
            "user",
            "user124",
            "system",
            self.now,
            {"ip_address": "5.6.7.8"}  # KP is in default blacklist
        )
        self.assertTrue(result, "Should detect blacklisted country KP")
    
    def test_impossible_travel_detection(self):
        # First login from New York (~40.7, -74.0)
        result1 = self.detector.instrument(
            "user_login",
            "user",
            "traveler123",
            "system",
            self.now - timedelta(minutes=10),  # 10 mins ago
            {"ip_address": "13.14.15.16"}  # New York
        )
        self.assertFalse(result1, "First login should be normal")

        # Second login from Tokyo (~35.7, 139.7) just 10 mins later
        result2 = self.detector.instrument(
            "user_login",
            "user",
            "traveler123",  # Same user!
            "system",
            self.now,  # Now
            {"ip_address": "9.10.11.12"}  # Tokyo
        )
        self.assertTrue(result2, "Should detect impossible travel (NY→Tokyo in 10 mins)")
    
    def test_normal_geo_access(self):
        result = self.detector.instrument(
            "user_login",
            "user",
            "user125",
            "system",
            self.now,
            {"ip_address": "8.8.8.8"}
        )
        self.assertFalse(result, "Normal IP should not trigger detection")