import psutil
from dataclasses import dataclass

@dataclass
class GuardConfig:
    min_free_gb: float = 10.0     
    max_cpu_pct: float = 85.0     
    max_active_downloads: int = 3 

def can_download(cfg: GuardConfig) -> bool:
    free_gb = psutil.disk_usage("/").free / (1024**3)
    cpu = psutil.cpu_percent(interval=0.2)
    return free_gb >= cfg.min_free_gb and cpu <= cfg.max_cpu_pct