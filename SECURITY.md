# Security

local-hands lets a Hermes instance on one machine run shell commands on another. That is a serious
capability. This page says what it protects, what it does not, and why.

## The short version

- A paired Hermes host (the "brain") **can run commands under your account** on the paired machine,
  within the approval mode you chose. This is remote code execution by design. It is **not a sandbox**.
- Pair only with a Hermes host you control. Treat the choice of `--approve auto` like handing that host
  an SSH key to your account.
- Keep the hub port off the public internet when you can (VPN, Tailscale, firewall).

## Who is trusted with what

| Party | Trusted to | Not trusted to |
|---|---|---|
| The brain (hub + Hermes) | send commands to paired machines | run anything on a machine that asks first without the user's answer |
| A paired machine | return output for its own commands | see or affect other machines; reach Hermes' control socket |
| The network between them | nothing | read or alter traffic; impersonate the brain |
| Other users on the brain host | nothing | talk to the hub's control socket or read its files |
| Anyone who can reach the port | download `hands.py` (public source) | pair, authenticate, or keep the hub busy |
| The model | propose commands through Hermes' `terminal` tool | skip Hermes' approvals or the machine's approvals |

## Mechanisms

**Transport.** TLS 1.2+ with a self-signed EC P-256 certificate created on first start. Because the
certificate is self-signed, clients cannot use CA or hostname verification (`ssl.CERT_NONE`); they
compare the SHA-256 of the server's SubjectPublicKeyInfo with the pin from the invite, in constant time,
**before sending the pairing code or the token**. A host with another key gets nothing. The `curl`
command printed by `hermes hands pair` applies the same pin to the download of `hands.py`.

**Pairing.** Codes are 120 random bits, single use, valid 10 minutes, stored hashed in memory only. The
code is consumed on first use whether or not the rest of the handshake completes.

**Machine tokens.** 256 random bits, issued once at pairing. The hub stores SHA-256(token) and compares
in constant time. `hermes hands revoke` deletes the record and disconnects the machine.

**Before authentication.** A peer that has not authenticated gets: at most 4 connections per address and
32 in total, one frame of at most 16 KiB, a hard deadline of 20 s for the whole exchange, and 8 failed
attempts per address and minute before it is refused outright. Frames are capped at 8 MiB after
authentication.

**Local control.** Hermes talks to the hub over a Unix socket created with mode 0600 inside a 0700
directory owned by the user; the hub refuses to use a directory it does not own. No TCP control port.

**Files.** Private key, device list, audit log and hub log are created 0600 in a 0700 directory. Tokens
and pairing codes are never logged.

**On the machine.** Commands run with `bash -c` in their own process group, so a timeout, `/stop`, a
lost connection or Ctrl-C kills the whole tree. Approval prompts time out to *refuse*. Without a
terminal, non-`auto` modes refuse everything. Typed-ahead keys are flushed before a question, and every
string received from the brain is stripped of control characters before it is displayed.

**Hermes' own guards.** The backend declares `skip_container_guards = False`: Hermes' dangerous-command
detection and approval flow apply to every command, exactly as on the local backend. There is no tool
that bypasses `terminal`.

## What it does not protect against

- **A malicious or compromised brain.** It can send any command. In `session` mode one "yes" covers
  the rest of that conversation; in `auto` mode nothing is asked. The session identifier is chosen by
  the brain, so a compromised brain can reuse an approved one.
- **A misleading prompt.** The one-line description in the prompt is supplied by the brain (it is the
  command the model asked for; the script that runs wraps it with Hermes' shell-state handling). A
  compromised brain could describe a script falsely. In `every` mode, `[v]` prints the exact script.
- **Prompt injection.** If the model is talked into a harmful command, the defences are Hermes'
  approvals and yours. Output from your machine goes to your model provider.
- **Confinement.** The workspace is a starting directory. Commands can read and write whatever your
  account can. Run the daemon as a restricted user, or inside a container or VM, if you want a boundary.
- **Local attackers on the machine.** Anyone who can read `~/.config/local-hands/` can impersonate that
  machine to the brain (and only that).
- **Denial of service** by someone who can flood the port. The pre-authentication limits keep the hub
  responsive against casual abuse; they do not keep it reachable under a volumetric attack.
- **Loss of the brain's private key.** Whoever holds `plugin-data/local-hands/tls/key.pem` can
  impersonate the brain to your machines. If it leaks: delete the `tls/` directory, restart the hub,
  pair again.

## Hardening checklist

- Bind the hub to a VPN address (`bind`) or firewall the port to your own addresses.
- Leave machines on `--approve session`; use `every` for anything sensitive.
- Review `hermes hands log` and `~/.config/local-hands/audit.jsonl` now and then.
- `hermes hands revoke <name>` for machines you no longer use; `python3 hands.py forget <brain>` on the
  machine.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository (Security → Report a vulnerability). Please do
not open a public issue for something exploitable.
