---
name: flow-handoff
description: Hand unfinished work to a teammate cleanly — committed, pushed on your person's word, summarised as done / left / start here, then quit the session.
---

# flow-handoff — leave the work where a teammate can pick it up

A handoff reaches another person, so first propose it to your own person in one sentence ("hand `cart-totals`
off to bob with this summary?") and do it only after a yes.

1. Check the tree: `git status`, then commit. Ask your person to push the branch — a push, the first one too, runs
   only on their word, never as your own step. After a yes, run `git push -u origin <branch>` (it asks the team for
   approval; wait for it). If the push is denied or times out, do not push another way — tell your person; the
   same command may be re-requested only on their explicit word.
2. Write the summary from your plan: **done** (what works, with the commits), **left** (what is open and why),
   **start here** (the first file or command for the next person), gotchas.
3. Call `handoff` with the summary and the teammate (`to`), or leave `to` empty for anyone. Your claims move with
   it. The answer may carry `push:` or `uncommitted:` hints — fix those first and hand off again.
4. Tell your person to quit this session: the work now belongs to the teammate who takes it; do not edit here
   afterwards.

<!-- flowmode-skill v2 -->
