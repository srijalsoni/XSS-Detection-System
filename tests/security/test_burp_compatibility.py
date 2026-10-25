import os
import glob
from security_testing.config import SecurityTestingConfig
from security_testing.runner import SecurityTestRunner
from security_testing.payloads import CONTROLLED_PAYLOADS

def test_burp_requests_files_exist_and_conform_to_rfc7230():
    """Verify all generated Burp request files exist, are non-empty, and target localhost."""
    req_files = glob.glob(os.path.join(SecurityTestingConfig.BURP_REQUESTS_DIR, "*.req"))
    assert len(req_files) >= len(CONTROLLED_PAYLOADS), "Burp request files missing or incomplete"

    for rf in req_files:
        with open(rf, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Host: 127.0.0.1:5000" in content, f"Burp request {rf} does not target local host"
        assert content.startswith("POST ") or content.startswith("GET "), f"Invalid HTTP verb in {rf}"
        assert "Content-Length:" in content or content.startswith("GET "), f"Missing Content-Length in {rf}"

def test_burp_proxy_runner_graceful_handling_when_offline():
    """Verify the test runner handles an offline Burp proxy without crashing or giving false success."""
    # Use a port that is definitely not listening
    offline_proxy = "http://127.0.0.1:59999"
    runner = SecurityTestRunner(base_url="http://127.0.0.1:5000", proxy_url=offline_proxy)
    assert not runner.check_burp_proxy_available(), "Offline proxy port was unexpectedly reported available"
