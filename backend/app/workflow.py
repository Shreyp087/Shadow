from vercel import workflow
from vercel.workflow._internal.py_sandbox import in_sandbox

if not in_sandbox():
    from app.workflow_transport import configure_workflow_transport
    configure_workflow_transport()

wf = workflow.Workflows()
