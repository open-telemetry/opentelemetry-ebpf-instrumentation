import asyncio
import gc
import threading

import requests


TASK_REUSE_BATCHES = 1_563
TASK_REUSE_BATCH_SIZE = 64
WORKER_TIMEOUT_SECONDS = 30
WORKER_POLL_INTERVAL_SECONDS = 0.01


class CancelledToThreadReuse:
    def __init__(self, backend_url: str):
        self.backend_url = backend_url
        self.states = {}

    def _run_worker(self, req_id: str, state: dict):
        state["worker_started"].set()
        if not state["release_worker"].wait(timeout=WORKER_TIMEOUT_SECONDS):
            state["worker_finished"].set()
            return

        try:
            response = requests.get(
                f"{self.backend_url}/cancelled-thread/{req_id}/1",
                timeout=WORKER_TIMEOUT_SECONDS,
            )
            state["worker_status"] = response.status_code
        finally:
            state["worker_finished"].set()

    async def start(self, req_id: str):
        state = {
            "worker_started": threading.Event(),
            "release_worker": threading.Event(),
            "worker_finished": threading.Event(),
            "worker_status": None,
        }
        self.states[req_id] = state

        task = asyncio.create_task(asyncio.to_thread(self._run_worker, req_id, state))
        while not state["worker_started"].is_set():
            await asyncio.sleep(0)

        state["task_address"] = id(task)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        del task
        gc.collect()

        return {"id": req_id, "status": "worker-blocked-owner-cancelled"}

    async def reuse(self, req_id: str):
        state = self.states.get(req_id)
        if state is None:
            raise RuntimeError(f"no cancelled worker for request {req_id}")

        reused_tasks = []
        reuse_attempt = 0
        try:
            current_task = asyncio.current_task()
            if id(current_task) == state["task_address"]:
                reused_tasks = [current_task]
            else:
                for batch in range(TASK_REUSE_BATCHES):
                    candidates = [
                        asyncio.create_task(asyncio.sleep(0))
                        for _ in range(TASK_REUSE_BATCH_SIZE)
                    ]
                    for index, candidate in enumerate(candidates):
                        if id(candidate) == state["task_address"]:
                            reused_tasks = candidates
                            reuse_attempt = batch * TASK_REUSE_BATCH_SIZE + index
                            break
                    if reused_tasks:
                        break
                    await asyncio.gather(*candidates)

            if not reused_tasks:
                raise RuntimeError("cancelled task address was not reused")

            state["release_worker"].set()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + WORKER_TIMEOUT_SECONDS
            while not state["worker_finished"].is_set():
                if loop.time() >= deadline:
                    break
                await asyncio.sleep(WORKER_POLL_INTERVAL_SECONDS)

            if not state["worker_finished"].is_set():
                raise RuntimeError("cancelled worker did not finish")
            if state["worker_status"] != 200:
                raise RuntimeError(
                    f"cancelled worker returned status {state['worker_status']}"
                )

            return {"id": req_id, "task_reused_after": reuse_attempt}
        finally:
            state["release_worker"].set()
            self.states.pop(req_id, None)
            tasks = [task for task in reused_tasks if task is not asyncio.current_task()]
            if tasks:
                await asyncio.gather(*tasks)
