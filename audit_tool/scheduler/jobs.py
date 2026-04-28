from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler


def build_scheduler(run_callable):
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_callable, "interval", weeks=1, id="weekly_audit", replace_existing=True)
    scheduler.start()
    return scheduler
