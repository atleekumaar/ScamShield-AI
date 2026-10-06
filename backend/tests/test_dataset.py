"""Dataset verification test evaluating sample messages against the threat analyzer."""

import json
from pathlib import Path
import pytest
from backend.app.models.schemas import AnalyzeRequest, Severity
from backend.app.services.llm_provider import MockLLMProvider
from backend.app.services.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def sample_messages():
    """Load sample dataset messages."""
    dataset_path = Path(__file__).resolve().parent.parent.parent / "data" / "sample_messages.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.anyio
async def test_dataset_malicious_messages(sample_messages):
    """Verify all malicious sample messages trigger high risk evaluations."""
    analyzer = ThreatAnalyzer(llm_provider=MockLLMProvider())
    malicious_samples = [m for m in sample_messages if m["expected_is_malicious"]]
    assert len(malicious_samples) >= 10

    for sample in malicious_samples:
        report = await analyzer.analyze(AnalyzeRequest(content=sample["text"]))
        assert report.risk_score >= 41.0, f"Failed for sample {sample['id']}: score {report.risk_score}"
        assert report.severity in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        assert len(report.recommended_actions) > 0


@pytest.mark.anyio
async def test_dataset_legitimate_messages(sample_messages):
    """Verify all legitimate messages do not trigger false positive phishing alarms."""
    analyzer = ThreatAnalyzer(llm_provider=MockLLMProvider())
    legitimate_samples = [m for m in sample_messages if not m["expected_is_malicious"]]
    assert len(legitimate_samples) >= 5

    for sample in legitimate_samples:
        report = await analyzer.analyze(AnalyzeRequest(content=sample["text"]))
        # Legitimate messages should stay SAFE or LOW
        assert report.risk_score <= 40.0, f"False positive for sample {sample['id']}: score {report.risk_score}"
        assert report.severity in [Severity.SAFE, Severity.LOW]
