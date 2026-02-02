import unittest
import sys
import os

class TestEnvironment(unittest.TestCase):
    def test_imports(self):
        """Test that necessary modules can be imported."""
        try:
            import paramiko
        except ImportError:
            self.fail("Could not import paramiko")

        try:
            import dotenv
        except ImportError:
            self.fail("Could not import dotenv")

    def test_daemon_path(self):
        """Test that daemon binary exists (if architecture matches)."""
        daemon_path = os.path.join(os.getcwd(), 'daemon', 'port-daemon')
        # We verify it exists; execution depends on architecture
        self.assertTrue(os.path.exists(daemon_path), "port-daemon binary not found")

if __name__ == '__main__':
    unittest.main()
