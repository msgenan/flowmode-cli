"""Caps on every free-text and id field (S10 F-10-02; docs/s10-audit/security.md F-04), shared by the REST models,
the MCP tools and the hooks, so a leaked token cannot grow the database and every SSE stream by megabytes. Over a cap:
422 (REST), a tool error (MCP). No imports, so the hooks stay cheap."""

MAX_ID_LEN = 500  # ids and names, repo, branch, worktree, task, external_id, issue url, task title, heartbeat activity
MAX_PATH_LEN = 1000  # claim and pin paths
MAX_TEXT_LEN = 4000  # plan, decision, message, approval reason, task note, decline reason, decision note
MAX_COMMAND_LEN = 2000  # an approval's command; the hook sends at most this much of a risky command
MAX_SUMMARY_LEN = 8000  # a handoff summary
MAX_READ_IDS = 200  # message ids marked read in one call
