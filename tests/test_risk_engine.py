import pytest
from core.risk_engine import calculate_risk

def test_calculate_risk_high_port():
    collected_data = [
        {
            "ip": "1.1.1.1",
            "port": 3389,
            "service": "RDP",
            "prefix": "1.1.1.0/24",
            "vulns_count": 0,
            "has_otx": False
        }
    ]
    asn = "AS123"
    total_time = 1.5

    result = calculate_risk(collected_data, asn, total_time)

    assert result["metrics"]["total_exposures"] == 1
    assert result["metrics"]["total_ips"] == 1
    assert result["metrics"]["total_score"] >= 10
    assert result["raw_data"][0]["risk_level"] == "Alto"

def test_calculate_risk_vulns():
    collected_data = [
        {
            "ip": "2.2.2.2",
            "port": 80,
            "service": "HTTP",
            "prefix": "2.2.2.0/24",
            "vulns_count": 3,
            "has_otx": False
        }
    ]
    asn = "AS123"
    total_time = 1.0

    result = calculate_risk(collected_data, asn, total_time)

    assert result["raw_data"][0]["score"] >= 10
    assert result["raw_data"][0]["risk_level"] == "Alto"

def test_calculate_risk_subdomain_bonus():
    collected_data = []
    asn = "AS123"
    total_time = 1.0

    result_no_subdomains = calculate_risk(collected_data, asn, total_time, subdomains_count=0)
    assert result_no_subdomains["metrics"]["total_score"] == 0

    result_with_subdomains = calculate_risk(collected_data, asn, total_time, subdomains_count=10)
    assert result_with_subdomains["metrics"]["total_score"] == 20

    result_max_bonus = calculate_risk(collected_data, asn, total_time, subdomains_count=100)
    assert result_max_bonus["metrics"]["total_score"] == 50
