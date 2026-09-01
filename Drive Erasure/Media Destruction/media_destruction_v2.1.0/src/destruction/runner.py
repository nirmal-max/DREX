from collections.abc import Callable, Mapping

from .audit import write
from .policy import plan
from .safety import guard


def make_plan(device, requested="best"):
    return plan(device, requested)


def execute_plan(device, executor: Callable | None = None, requested="best", out="evidence"):
    """Execute only through an explicitly supplied, qualified hardware adapter.

    Planning and physical destruction are deliberately separate.  This function
    never treats a plan as an execution result and never provides an improvised
    machine-control implementation.
    """
    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)
    if executor is None or not callable(executor):
        record = {
            "plan": p.to_dict(),
            "status": "EXECUTOR_REQUIRED",
            "reason": "No qualified physical-destruction executor was supplied.",
        }
        return {**record, "evidence": write(out, record)}

    result = executor(device, p)
    if not isinstance(result, Mapping):
        raise TypeError("destruction executor must return a mapping")
    if result.get("status") != "EXECUTED":
        record = {
            "plan": p.to_dict(),
            "status": "EXECUTION_NOT_VERIFIED",
            "executor_result": dict(result),
        }
        return {**record, "evidence": write(out, record)}

    evidence = result.get("evidence")
    if not evidence:
        raise ValueError("physical execution requires machine evidence")
    record = {
        "plan": p.to_dict(),
        "status": "EXECUTED",
        "executor_result": dict(result),
    }
    return {**record, "evidence": write(out, record)}
