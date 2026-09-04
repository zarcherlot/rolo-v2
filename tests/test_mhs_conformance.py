from rolo.mhs_conformance import validate_read_only_surface


def test_unapproved_bus_and_gpio_access_fail_closed() -> None:
    violations = validate_read_only_surface(
        operations=["inspect", "status", "read"],
        references=[
            {"transport": "I2C", "access": "READ_ONLY"},
            {"transport": "GPIO", "access": "READ_ONLY", "approved_access": True},
        ],
    )
    assert violations == ["unapproved I2C access"]


def test_write_like_operations_are_rejected() -> None:
    violations = validate_read_only_surface(operations=["read", "setpoint", "reset"])
    assert "write-like operation exposed: setpoint" in violations
    assert "write-like operation exposed: reset" in violations
