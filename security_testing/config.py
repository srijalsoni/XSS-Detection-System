import os

class SecurityTestingConfig:
    """Configuration for local controlled security testing and Burp Suite proxy integration."""
    
    # Strictly localhost / loopback targets only
    BASE_URL = os.environ.get("TEST_APP_URL", "http://127.0.0.1:5000")
    APP_HOST = "127.0.0.1"
    APP_PORT = int(os.environ.get("TEST_APP_PORT", 5000))
    
    # Burp Suite default local proxy listener
    BURP_PROXY_URL = os.environ.get("BURP_PROXY_URL", "http://127.0.0.1:8080")
    
    # Timeouts and bounds
    REQUEST_TIMEOUT = 5.0  # seconds
    MAX_PAYLOAD_LENGTH = 4096
    
    # Report outputs
    REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    BURP_REQUESTS_DIR = os.path.join(os.path.dirname(__file__), "burp_requests")
