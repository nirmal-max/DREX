from .policy import plan
from .safety import guard
from .audit import write
def make_plan(device,requested="best"): return plan(device,requested)
def execute_plan(device,requested="best",out="evidence"):
    p=plan(device,requested); guard(device,True)
    if p.outcome!="PLANNED": raise RuntimeError(p.rationale)
    return {"plan":p.to_dict(),"status":"PLANNED_FOR_EXECUTION","evidence":write(out,{"plan":p.to_dict(),"status":"PLANNED_FOR_EXECUTION"})}
