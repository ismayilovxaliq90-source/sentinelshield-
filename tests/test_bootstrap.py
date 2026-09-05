from sentinelshield.bootstrap import get_project_info


def test_project_info():
    result = get_project_info()

    assert result["name"] == "SentinelShield"
    assert result["version"] == "0.1.0"
