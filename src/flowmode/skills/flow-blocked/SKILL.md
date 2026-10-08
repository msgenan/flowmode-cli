---
name: flow-blocked
description: What to do when Flowmode stops you — a claim on a file, a denied or timed-out push, a low usage limit, an unreachable server, a session on main, a branch that conflicts with main.
---

# flow-blocked — the playbook when something blocks you

The line that does not move: anything that reaches another person — a file request, a handoff, a message, a
push (the first one too) — you propose to your own person in one sentence and do only after a yes. You never decide
these alone, and you never work around a block while you wait. Ask your person before you send a file request, a
handoff or a message to anyone.

## A file is claimed by a teammate
The edit is denied and the reason names who holds it. Do not work around the claim: no `sed -i`, no `echo >`
redirect, no `cp`/`mv` onto the file, no script that writes it, no rename — those are edits too and are refused.
Tell your person in one sentence: which file, who holds it, what you need to change and why. Continue with other
files of your task. When nothing else is left, propose a handoff or another task.

## A push (or another risky command) was denied or timed out
Stop. Never run it another way: no different flags, no script, no other tool. Tell your person what was asked
and the answer. The same command may be re-requested only on the person's explicit word ("ask again"); then you
run the very same command again and wait for the approval. An approval that was given but failed (the branch is
not on origin, a read-only collaborator) is reported to you after the command: tell your person, never retry on
your own.

## Your usage limit or context is running low
Before you stop mid-task, offer a handoff: commit, ask your person to push the branch — a push runs only on their
word, then waits for the team's approval — write done / left / start here, and ask your person whether to hand it
to a teammate (`flow-handoff`).

## The server is unreachable
Edits are allowed but claims are not recorded; risky commands are refused without asking anyone. Keep working on
your task, tell your person that claims are not recorded, and do not retry risky commands another way. Your
person restarts the session when the server is back.

## You are on main (the default branch)
Edits here are refused: "start or take a task first". Tell your person to run `flowmode work` in a terminal — it
lists their tasks, opens the task's worktree and launches the agent there. To take or start a task from inside
this session, use `accept_task` or `start_task` only after your person said so, then send them to `flowmode work`.

## Your branch conflicts with main
`flowmode check` or the session context says `conflicts with main: <files>`: main moved on under your task. Ask your
person, in one sentence, whether to merge `origin/<default>` into the branch (never rebase, never force push). Only
after a yes: merge it, resolve in main's favour where your task does not own the change, then re-run the checks.

## The checkout was moved
The context says the `.git` file points at a missing directory. Tell your person to run `git worktree repair` in
the main checkout and to restart the session; nothing works there until then.

<!-- flowmode-skill v2 -->
