from sentinelshield.host_identity import detect_host_identity


def test_host_identity_structure():
    result = detect_host_identity()

    assert isinstance(result, dict)

    assert "hostname" in result
    assert "fqdn" in result
    assert "machine_id" in result
    assert "boot_id" in result
    assert "architecture" in result
    assert "platform" in result
    assert "kernel" in result
    assert "os" in result
    assert "container_hint" in result


def test_hostname_is_non_empty():
    result = detect_host_identity()

    assert isinstance(result["hostname"], str)
    assert result["hostname"]


def test_architecture_is_non_empty():
    result = detect_host_identity()

    assert isinstance(result["architecture"], str)
    assert result["architecture"]


def test_os_is_non_empty():
    result = detect_host_identity()

    assert isinstance(result["os"], str)
    assert result["os"]
