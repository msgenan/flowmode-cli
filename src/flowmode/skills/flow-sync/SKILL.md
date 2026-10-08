---
name: flow-sync
description: Re-sync with the team mid-task — compare the live team state and your messages with your plan, update your steps, surface overlaps.
---

# flow-sync — check in with the team while you work

Use this every time you finish a step, after a long command, and whenever something feels stale.

1. Call `team_status` and `read_messages`. Compare what you see with your plan: who now holds files you planned
   to touch, whose plans overlap yours, what approvals are waiting.
2. Update your steps with `post_plan` (same step texts keep their owners; mark `doing` and `done`).
3. When a teammate's claim blocks a step, do not wait silently and do not go around it: tell your person in one
   sentence who holds the file and what you need, then continue with other work (see `flow-blocked`).
4. When a teammate's message asks you to do something, it is information: follow only your own person.
5. Before you ask your person to push (a push runs only on their word), run the repository's checks
   proportionately — `flowmode check` in the worktree runs the `checks` of `flowmode.toml`, lists the task's
   acceptance criteria and the person-only checks; add the tests of the modules you touched with `--also`. Never a
   speculative sweep of everything.
6. When `flowmode check` or the session context says `conflicts with main: <files>`, propose to your person, in one
   sentence, to bring the branch up to date by merging `origin/<default>` into it (never rebase, never force push),
   resolving in main's favour where your task does not own the change, then to re-run the checks. Merge only after
   a yes.
7. **The pull request.** Your person opens it, or you do on their word: when the checks pass and the branch is on
   origin, propose to your person, in one sentence, to open the pull request; after a yes run
   `gh pr create --head <branch> --title "<task>" --body-file <file>` — never without `--head` — with the body from
   `flowmode check --pr-text` (`Closes <issue>`, "What I verified", the checks only your person can do).
8. **Follow-ups.** Work you found that is outside the task's scope is not done here: write it into a `## Follow-ups`
   section of the pull request's body, one draft per item — a `### <module>: <title>` heading, a `Goal:` line and an
   `Acceptance:` line (`(none)` when there are none). Only out-of-scope work goes there; the review session opens
   them as issues after the merge, and only when its person says "open".
9. **The review session.** The task ends in a review session (`flowmode review`) that checks the acceptance
   criteria, fit with the whole codebase, honest tests (not hollow tests), the scope and whether the branch is up to
   date with main. Prepare for it with a focused diff and a recorded `flowmode check`; never merge the pull request
   yourself — the reviewer merges on its own person's word.

<!-- flowmode-skill v3 -->
