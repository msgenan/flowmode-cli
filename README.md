# Flowmode CLI

## What it is

The Flowmode command-line client connects this computer's coding agents (Claude Code and Codex) to the team's Flowmode server. It holds no server.

## Requirements

macOS or Linux, or Windows through WSL. You need `git` and `curl`.

## Set up

Copy the line from the "Set up your computer" card on the team's Flowmode page and paste it into your terminal:

```sh
git clone https://github.com/msgenan/flowmode-cli && cd flowmode-cli && ./setup.sh <server> <code>
```

The card fills in the server address and a one-time code. The code works once and expires within 10 minutes.

## Without a code

For SSH access or a machine with no browser, run:

`./setup.sh <server>`

This signs in with GitHub using device flow (`flowmode login --server <server>`). Follow the instructions to finish signing in from a browser on another computer.

## What setup.sh installs

If uv is missing, `setup.sh` installs uv 0.12.10 from Astral's versioned installer at `https://astral.sh/uv/0.12.10/install.sh`. It installs Python through uv if missing, then installs the `flowmode` command with the clone's pinned dependency versions.

It changes no shell rc file. If the tool folder is not on PATH, it prints one line saying how to add it.

## Update

From the clone, run `git pull && ./setup.sh`. With no argument, setup only installs or updates; it keeps your sign-in.

## Shared machines

On a computer other users share, the one-time code is visible to them in the process list while `setup.sh` runs. Use `./setup.sh <server>` (GitHub sign-in) instead of a code there.

## Uninstall

Run `uv tool uninstall flowmode`. Your settings stay in `~/.flowmode`; delete that folder to remove them.

## Licence

Use-only licence, see LICENSE.
