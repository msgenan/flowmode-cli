"""Thin synchronous client for the Flowmode REST API. Never sends file contents."""

import httpx

# S14 F-14-15 / S17 F-17-31 (L-31-1, L-31-6): the 401 detail for an old `fm_` member token the server still knows. The
# server sends it, the hooks show it as is (from the 401 and this detail); it lives here so the hooks need not import
# the server side.
OLD_TOKEN_DETAIL = "old tokens are turned off; run flowmode login"  # noqa: S105 — a message, not a secret
# S20 C1c (F-20-96, walkthrough F13): the 401 detail for a device token whose membership ended (the person was removed
# or left): no guess, so the CLI can say "you are no longer in workspace <name>" instead of "token rejected".
MEMBERSHIP_ENDED_DETAIL = "membership ended: this device's workspace membership was removed or left"

# S10 F-10-06: heartbeats and note lookups are best effort — a stuck server must not hold the agent for long.
BEST_EFFORT_TIMEOUT = httpx.Timeout(connect=1.0, read=2.0, write=2.0, pool=1.0)


class ServerUnreachable(Exception):
    """Connect error, timeout, DNS failure or a 5xx answer."""


class ApiError(Exception):
    """A 4xx answer."""

    def __init__(self, status: int, detail: str, body: dict):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
        self.body = body


def _params(**kwargs) -> dict:
    return {k: v for k, v in kwargs.items() if v is not None}


def _timeout(best_effort: bool) -> dict:
    """Request kwargs: the short best-effort timeout, or nothing (the client's own timeout)."""
    return {"timeout": BEST_EFFORT_TIMEOUT} if best_effort else {}


class ApiClient:
    def __init__(
        self,
        server_url: str,
        token: str | None,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ):
        """`token=None` is the token-less mode of `flowmode login` (S14 F-14-13): no Authorization header at all,
        for the two public device-flow routes only — a stale bearer never rides along."""
        self._root = server_url.rstrip("/")
        self._http = httpx.Client(
            base_url=self._root + "/api",
            headers={"Authorization": f"Bearer {token}"} if token is not None else {},
            timeout=timeout,
            transport=transport,
        )
        # S20 F-20-99: a call made with the member's own timeout timed out (the hook remembers it). A refused
        # connection does not set it: it fails in milliseconds, and remembering it would keep claims unrecorded for
        # the window after the server is back (D5 1f). A best-effort call (its own short `timeout`) never sets it.
        self.transport_failed = False

    def _request(self, method: str, path: str, **kwargs) -> tuple[int, object]:
        try:
            r = self._http.request(method, path, **kwargs)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:  # ConnectError is a NetworkError
            if isinstance(exc, httpx.TimeoutException) and "timeout" not in kwargs:
                self.transport_failed = True
            raise ServerUnreachable(str(exc) or type(exc).__name__) from exc
        if r.status_code >= 500:
            raise ServerUnreachable(f"server error {r.status_code}")
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code >= 400:
            detail = body.get("detail", r.text) if isinstance(body, dict) else r.text
            raise ApiError(r.status_code, str(detail), body if isinstance(body, dict) else {})
        return r.status_code, body

    def _get(self, path: str, best_effort: bool = False, **params):
        return self._request("GET", path, params=_params(**params), **_timeout(best_effort))[1]

    def _post(self, path: str, body: dict | None = None, best_effort: bool = False):
        return self._request("POST", path, json=body, **_timeout(best_effort))[1]

    def me(self) -> dict:
        return self._get("/me")

    # S14 F-14-13: `flowmode login` / `logout`

    def _device(self, path: str, body: dict) -> tuple[int, dict]:
        """POST to a public device-flow route (outside /api) on a token-less client: (status, JSON object) for
        every answer the route gives — the CLI turns each into one sentence; ServerUnreachable when nothing came."""
        if "authorization" in self._http.headers:
            raise ValueError("the device-flow routes are called without a token")
        try:
            r = self._http.post(self._root + path, json=body)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise ServerUnreachable(str(exc) or type(exc).__name__) from exc
        try:
            answer = r.json()
        except ValueError:
            answer = {}
        return r.status_code, answer if isinstance(answer, dict) else {}

    def device_start(self, name: str, workspace: str | None = None, repo: str | None = None) -> tuple[int, dict]:
        """S19 §4.3: `workspace` (an id) or the clone's `repo` say which membership the token is for."""
        return self._device("/auth/device/start", {"name": name, **_params(workspace=workspace, repo=repo)})

    def device_poll(self, handle: str) -> tuple[int, dict]:
        return self._device("/auth/device/poll", {"handle": handle})

    def connect_redeem(self, code: str, name: str) -> tuple[int, dict]:
        """S17 F-17-11: `flowmode login --code` — the code in the JSON body only, on the same token-less client."""
        return self._device("/auth/connect/redeem", {"code": code, "name": name})

    def revoke_current_device(self) -> dict:
        return self._request("DELETE", "/account/devices/current")[1]

    def health(self) -> dict:
        """S20 L-10: `{"status", "version"}` — the server's release (no token needed)."""
        return self._get("/health")

    def config(self) -> dict:
        return self._get("/config")

    def register_session(self, body: dict) -> dict:
        return self._post("/sessions", body)

    def heartbeat(
        self,
        session_id,
        activity: str | None = None,
        hold: bool = False,
        idle: bool = False,
        best_effort: bool = False,
        push_state: dict | None = None,
    ) -> dict:
        """`best_effort`: give up after BEST_EFFORT_TIMEOUT instead of the member's request timeout. `push_state`
        (S11 F-11-40) is sent only when given: without it the server keeps the last one."""
        body = {
            "activity": activity,
            **({"hold": True} if hold else {}),
            **({"idle": True} if idle else {}),
            **({"push_state": push_state} if push_state is not None else {}),
        }
        return self._post(f"/sessions/{session_id}/heartbeat", body, best_effort=best_effort)

    def get_session(self, session_id) -> dict:
        return self._get(f"/sessions/{session_id}")

    def end_session(self, session_id, reason: str = "hook") -> dict:
        """S12 F-12-03: `reason` is who ends it — `hook` (SessionEnd), `member` or `watcher`."""
        return self._post(f"/sessions/{session_id}/end", {"reason": reason})

    def claim(self, session_id, path, ttl_seconds=None) -> tuple[int, dict]:
        return self._request("POST", "/claims", json=_params(session_id=session_id, path=path, ttl_seconds=ttl_seconds))

    def release_claim(self, session_id, path) -> dict:
        """S20 C1a (walkthrough F6): give back a claim this session made for a command that never ran."""
        return self._post("/claims/release", {"session_id": session_id, "path": path}, best_effort=True)

    def list_sessions(self, repo=None, member=None, status=None) -> list[dict]:
        return self._get("/sessions", repo=repo, member=member, status=status)

    def list_claims(self, repo=None, session_id=None, member=None) -> list[dict]:
        return self._get("/claims", repo=repo, session_id=session_id, member=member)

    def list_claim_denials(self, limit=None) -> list[dict]:
        return self._get("/claims/denied", limit=limit)

    def list_plans(self, repo=None, session_id=None, latest=None) -> list[dict]:
        return self._get("/plans", repo=repo, session_id=session_id, latest="true" if latest else None)

    def list_decisions(self, repo=None, session_id=None) -> list[dict]:
        return self._get("/decisions", repo=repo, session_id=session_id)

    def list_approvals(self, status=None, repo=None) -> list[dict]:
        return self._get("/approvals", status=status, repo=repo)

    def request_approval(
        self, session_id, command, reason, timeout_seconds, diffstat=None, ahead=None, conflicts=None
    ) -> dict:
        body = {"session_id": session_id, "command": command, "reason": reason, "timeout_seconds": timeout_seconds}
        if diffstat is not None:
            body["diffstat"] = diffstat
        if ahead is not None:
            body["ahead"] = ahead
        if conflicts is not None:  # S11 F-11-45
            body["conflicts"] = conflicts
        return self._post("/approvals", body)

    def report_outcome(
        self, approval_id, outcome: str, detail: str | None = None, remote_ref: bool | None = None
    ) -> dict:
        """S11 F-11-30: how an approved command went (best effort: the PostToolUse hook must stay quick)."""
        body = {"outcome": outcome, "detail": detail, "remote_ref": remote_ref}
        return self._post(f"/approvals/{approval_id}/outcome", body, best_effort=True)

    def get_approval(self, approval_id, wait: float = 0) -> dict:
        params = {"wait": wait} if wait else {}
        return self._request("GET", f"/approvals/{approval_id}", params=params, timeout=wait + 5)[1]

    # S17 F-17-13: `flowmode rehearse` (the server fixes the command text; nothing is sent)

    def create_rehearsal(self) -> dict:
        return self._post("/rehearsals", {})

    def get_rehearsal(self, rehearsal_id: str, wait: float = 0) -> dict:
        params = {"wait": wait} if wait else {}
        return self._request("GET", f"/rehearsals/{rehearsal_id}", params=params, timeout=wait + 5)[1]

    # S17 F-17-12: the repo report (`flowmode doctor`, and best effort at the end of `flowmode install`)

    def post_facts(self, body: dict, best_effort: bool = False) -> dict:
        return self._post("/me/facts", body, best_effort=best_effort)

    def my_cards(self, best_effort: bool = False) -> dict:
        return self._get("/me/cards", best_effort=best_effort)

    def handoff(self, session_id, summary, to=None) -> dict:
        return self._post(f"/sessions/{session_id}/handoff", {"summary": summary, "to": to})

    def list_handoffs(self, id=None, to=None, repo=None, status=None) -> list[dict]:
        return self._get("/handoffs", id=id, to=to, repo=repo, status=status)

    def list_messages(self, unread=None, session_id=None, best_effort: bool = False) -> list[dict]:
        return self._get("/messages", best_effort=best_effort, unread="true" if unread else None, session_id=session_id)

    def mark_messages_read(self, ids) -> list[dict]:
        return self._post("/messages/read", {"ids": list(ids)})

    def create_task(self, name, repo, branch) -> dict:
        """ApiError 409 carries the existing task in body["task"]."""
        return self._post("/tasks", {"name": name, "repo": repo, "branch": branch})

    def list_tasks(self, repo=None, owner=None, status=None, id=None, name=None, assigned_by=None) -> list[dict]:
        return self._get("/tasks", repo=repo, owner=owner, status=status, id=id, name=name, assigned_by=assigned_by)

    def assign_task(self, to, repo, name, title=None, note=None, branch=None, issue_url=None, issue_body=None) -> dict:
        """ApiError 409 carries the existing task in body["task"]."""
        return self._post(
            "/tasks/assign",
            _params(
                to=to,
                repo=repo,
                name=name,
                title=title,
                note=note,
                branch=branch,
                issue_url=issue_url,
                issue_body=issue_body,
            ),
        )

    def record_read(self, task_id, path) -> dict:
        """S11 F-11-28: a required file was read (best effort: the PostToolUse hook stays quick)."""
        return self._post(f"/tasks/{task_id}/reads", {"path": path}, best_effort=True)

    def report_checks(self, task_id, rows: list[dict], run: bool = True) -> list[dict]:
        """S11 F-11-29: store a `flowmode check` run's rows (or marks, run=False); every row of the task back."""
        return self._post(f"/tasks/{task_id}/checks", {"rows": rows, "run": run})

    def list_checks(self, task_id) -> list[dict]:
        return self._get(f"/tasks/{task_id}/checks")

    def report_pr(self, task_id, body: dict) -> dict:
        """S12 F-12-10: the task's pull request as the member's own gh sees it (facts only; §8.2)."""
        return self._post(f"/tasks/{task_id}/pr", body)

    def sync_repo(self, body: dict) -> dict:
        """S13 F-13-01: a `flowmode pr sync` report of the repo's pull requests and open issues (facts, titles and
        closing references; never a body) → the counts, or {"ignored": "repo"} / {"skipped": "recent"}."""
        return self._post("/repos/sync", body)

    def tree_head(self, repo) -> dict | None:
        """S13 F-13-20: the meta of the tree the server holds for `repo` (sha, committed_at, …; never a path), or
        None when no member has sent one."""
        heads = self._get("/repos/trees", repo=repo)
        return heads[0] if heads else None

    def report_tree(self, body: dict) -> dict:
        """S13 F-13-20: the default branch's path list (paths only, never contents) → {"ok", "sha", "count",
        "skipped", "truncated"} | {"unchanged": true} | {"ignored": "repo"}; a newer stored commit is ApiError 409
        whose body carries {"kept": sha}."""
        return self._post("/repos/tree", body)

    def list_pulls(self, repo=None, state=None) -> list[dict]:
        return self._get("/pulls", repo=repo, state=state)

    def get_pull(self, repo, number) -> dict:
        return self._get("/pulls/one", repo=repo, number=number)

    def take_fix(self, repo, number) -> dict:
        """S12 F-12-12: {"action": "continue" | "created", "task"} or {"action": "requested", "request"}."""
        return self._post("/pulls/fix", {"repo": repo, "number": number})

    def list_task_requests(self, repo=None, status=None) -> list[dict]:
        return self._get("/task-requests", repo=repo, status=status)

    def decide_task_request(self, request_id, action: str, reason=None) -> dict:
        """`action` allow | deny | withdraw."""
        return self._post(f"/task-requests/{request_id}/{action}", _params(reason=reason))

    # S12 F-12-13: the Flowmode review of a task's pull request
    def get_review(self, task_id) -> dict:
        return self._get(f"/tasks/{task_id}/review")

    def post_verdict(
        self,
        task_id,
        verdict: str,
        notes: str | None = None,
        head_sha: str | None = None,
        blocking: list[str] | None = None,
    ) -> dict:
        body = {
            "verdict": verdict,
            "notes": notes,
            "head_sha": head_sha,
            **({"blocking": blocking} if blocking else {}),
        }
        return self._post(f"/tasks/{task_id}/review", body)

    def pass_review(self, task_id, to: str, updated_with_main: bool | None = None) -> dict:
        return self._post(f"/tasks/{task_id}/review/pass", {"to": to, "updated_with_main": updated_with_main})

    def answer_review(self, task_id, action: str, reason: str | None = None) -> dict:
        """accept / decline (with an optional reason) / withdraw a passed review."""
        return self._post(f"/tasks/{task_id}/review/{action}", {"reason": reason} if action == "decline" else None)

    # S12 F-12-13b: follow-up issues after the merge (no decide call here: that takes the person's approver key)
    def list_followups(self, task_id) -> list[dict]:
        return self._get(f"/tasks/{task_id}/followups")

    def propose_followups(self, task_id, drafts: list[dict]) -> list[dict]:
        return self._post(f"/tasks/{task_id}/followups", {"drafts": drafts})

    def followup_opening(self, task_id, followup_id: str) -> dict:
        """Claim an approved row before gh creates its issue (409: another run has it)."""
        return self._post(f"/tasks/{task_id}/followups/{followup_id}/opening")

    def followup_release(self, task_id, followup_id: str) -> dict:
        return self._request("DELETE", f"/tasks/{task_id}/followups/{followup_id}/opening")[1]

    def followup_opened(self, task_id, followup_id: str, issue_url: str) -> dict:
        return self._post(f"/tasks/{task_id}/followups/{followup_id}/opened", {"issue_url": issue_url})

    def list_modules(self, repo=None) -> list[dict]:
        return self._get("/modules", repo=repo)

    def accept_task(self, task_id) -> dict:
        return self._post("/tasks/accept", {"id": task_id})

    def decline_task(self, task_id, reason=None) -> dict:
        return self._post("/tasks/decline", _params(id=task_id, reason=reason))

    def resend_task(self, task_id, to=None) -> dict:
        return self._post("/tasks/resend", _params(id=task_id, to=to))

    def cancel_task(self, task_id) -> dict:
        return self._post("/tasks/cancel", {"id": task_id})

    def delete_task(self, task_id) -> dict:
        """S11 F-11-34: the task as it was before the delete."""
        return self._request("DELETE", f"/tasks/{task_id}")[1]

    def start_task(self, task_id, branch=None, worktree=None) -> dict:
        return self._post("/tasks/start", _params(id=task_id, branch=branch, worktree=worktree))

    def finish_task(self, task_id) -> dict:
        return self._post("/tasks/done", {"id": task_id})

    def release_task(self, task_id, note=None) -> dict:
        """S20 §4.4: the owner or a leader gives the task back to the team."""
        return self._post(f"/tasks/{task_id}/release", _params(note=note))

    def take_task(self, task_id) -> dict:
        """S20 §4.4: take a released task (you become its owner)."""
        return self._post(f"/tasks/{task_id}/take")

    def take_handoff(self, handoff_id, session_id=None) -> dict:
        """{"handoff", "claims", "skipped"}."""
        return self._post("/handoffs/take", _params(id=handoff_id, session_id=session_id))

    def list_pins(self, repo=None, path=None) -> list[dict]:
        return self._request("GET", "/pins", params=_params(repo=repo, path=path))[1]  # `path` is a query key here

    def create_pin(self, repo, path, text, commit=None) -> dict:
        return self._post("/pins", _params(repo=repo, path=path, text=text, commit=commit))

    def overlap(self, session_id=None, paths=None):
        """{session_id, items} for one session, or [{session_id, items}] for every live session with items."""
        return self._get("/overlap", session_id=session_id, paths=list(paths) if paths else None)

    def post_chat(self, text) -> dict:
        return self._post("/chat", {"text": text})

    def close(self):
        self._http.close()
