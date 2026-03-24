from .analytics import router as analytics_router
from .attack_runs import router as attack_runs_router
from .health import router as health_router
from .target_systems import router as target_systems_router

__all__ = [
    "analytics_router",
    "attack_runs_router",
    "health_router",
    "target_systems_router",
]
