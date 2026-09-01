import sys
sys.path.insert(0, "src")

import json
from pathlib import Path

import pytest

from destruction.models import Device
from destruction.runner import execute_plan


def qualified_device():
    return Device(
        "/dev/test",
        "HDD",
        size_bytes=100,
        capabilities={
            "destruction_equipment_qualified": True,
            "qualified_media": ["HDD"],
        },
    )


def test_execute_requires_real_executor(tmp_path):
    result = execute_plan(qualified_device(), out=str(tmp_path))
    assert result["status"] == "EXECUTOR_REQUIRED"
    assert json.loads(Path(result["evidence"]).read_text())["status"] == "EXECUTOR_REQUIRED"


def test_executor_must_return_mapping(tmp_path):
    with pytest.raises(TypeError):
        execute_plan(qualified_device(), executor=lambda device, plan: None, out=str(tmp_path))


def test_executor_failure_is_not_success(tmp_path):
    def executor(device, plan):
        return {"status": "FAILED", "reason": "machine rejected job"}

    result = execute_plan(qualified_device(), executor=executor, out=str(tmp_path))
    assert result["status"] == "EXECUTION_NOT_VERIFIED"


def test_execution_requires_machine_evidence(tmp_path):
    def executor(device, plan):
        return {"status": "EXECUTED"}

    with pytest.raises(ValueError, match="machine evidence"):
        execute_plan(qualified_device(), executor=executor, out=str(tmp_path))


def test_success_requires_executor_evidence(tmp_path):
    def executor(device, plan):
        return {"status": "EXECUTED", "evidence": {"machine_event": "E-123"}}

    result = execute_plan(qualified_device(), executor=executor, out=str(tmp_path))
    assert result["status"] == "EXECUTED"
    evidence = json.loads(Path(result["evidence"]).read_text())
    assert evidence["status"] == "EXECUTED"
    assert evidence["executor_result"]["evidence"]["machine_event"] == "E-123"
