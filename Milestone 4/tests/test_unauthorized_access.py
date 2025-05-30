import unittest
from datetime import datetime
from smart_home_security.detectors import UnauthorizedAccessDetector
from smart_home_security import AttackDetector

# unit tests for UnauthorizedAccessDetector
class TestUnauthorizedAccessDetector(unittest.TestCase):  
    def setUp(self):
        self.detector = UnauthorizedAccessDetector()
        self.allowed_roles = ["ADMIN", "MANAGER"]
    
    def test_authorized_admin(self):
        self.assertFalse(self.detector.detect("ADMIN", self.allowed_roles))
    
    def test_authorized_manager(self):
        self.assertFalse(self.detector.detect("MANAGER", self.allowed_roles))
    
    def test_unauthorized_user(self):
        self.assertTrue(self.detector.detect("USER", self.allowed_roles))
    
    def test_unauthorized_guest(self):
        self.assertTrue(self.detector.detect("GUEST", ["ADMIN"]))
    
    def test_empty_allowed_roles(self):
        self.assertTrue(self.detector.detect("ADMIN", []))
    
    def test_event_data_generation(self):
        event_data = self.detector.get_event_data(
            user_role="USER",
            allowed_roles=self.allowed_roles,
            timestamp="2023-01-01T12:00:00Z",
            user_id="user123",
            source_id="192.168.1.1"
        )
        
        self.assertEqual(event_data["user_role"], "USER")
        self.assertEqual(event_data["allowed_roles"], ["ADMIN", "MANAGER"])
        self.assertIn("unauthorized_access_attempt", event_data["event"])

# integration tests for UnauthorizedAccessDetector within AttackDetector
class TestUnauthorizedAccessIntegration(unittest.TestCase):
    def setUp(self):
        self.detector = AttackDetector()
    
    def test_authorized_admin_command(self):
        result = self.detector.instrument(
            event_name="admin_command",
            user_role="ADMIN",
            user_id="admin1",
            source_id="192.168.1.100",
            timestamp=datetime.now(),
            context={"allowed_roles": ["ADMIN"], "action": "reboot"}
        )
        self.assertFalse(result)
    
    def test_unauthorized_user_command(self):
        result = self.detector.instrument(
            event_name="admin_command",
            user_role="USER",
            user_id="user1",
            source_id="192.168.1.1",
            timestamp=datetime.now(),
            context={"allowed_roles": ["ADMIN"], "action": "reboot"}
        )
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()