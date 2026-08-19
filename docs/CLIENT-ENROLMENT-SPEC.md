# Client spec: entering an invite code on the 3DS

Server side is done and tested (`server/` v1.1.0). This is what the console
build has to do. Nothing here needs new crypto — enrolment reuses the session
the handshake already established.

## Why this exists

The allowlist is a list of 32-byte console public keys. Getting one off a 3DS
and onto the server means moving 64 hex characters between two devices that
share no clipboard. An invite inverts the direction: the operator sends a short
code, the player types it in once, and the console's key writes itself into the
allowlist.

**It is a one-time introduction, not a password.** After a successful
enrolment the console is an ordinary allowlist entry and connects normally
forever after, with no code and nothing for the operator to accept.

## The wire

Two new packet types in `proto/bs_proto.h`, already shared verbatim:

```c
BS_PKT_ENROL      = 0x08, /* C->S  AEAD, one-time invite code as text    */
BS_PKT_ENROL_OK   = 0x09  /* S->C  AEAD, empty; you are on the allowlist */
```

`BS_PKT_ENROL` is framed **exactly like `BS_PKT_DATA`** — same header, same
session id, same message id, same `hydro_secretbox_encrypt` under
`BS_CTX_C2S` with `keys.tx`. Only the type byte differs. The payload is the
code as plain text, no NUL terminator required, at most `BS_INVITE_CODE_MAX`
(32) bytes.

`BS_PKT_ENROL_OK` comes back framed like a server `DATA`: decrypt it under
`BS_CTX_S2C` with `keys.rx`. Its payload is empty; the packet arriving at all
is the message.

## The flow

1. Handshake exactly as now — HELLO, COOKIE, KX1, KX2, KX3. This succeeds
   whether or not the console is on the allowlist; the allowlist check happens
   after `hydro_kx_xx_4` on the server, and an unlisted key is simply never
   spoken to again.
2. If the console is **already enrolled**, the server starts sending it traffic
   and the join proceeds as it does today. Nothing changes.
3. If it is **not** on the allowlist and an invite is armed, the server creates
   a silent probation session and waits. The console cannot tell the difference
   between this and being dropped — there is no "please enter a code" prompt
   from the server, by design.
4. The console sends `BS_PKT_ENROL` with the typed code.
5. Correct → `BS_PKT_ENROL_OK` comes back, followed immediately by the normal
   join traffic. Wrong, or no invite armed, or too late → **nothing comes back
   and the session is discarded**.

## What the console has to implement

- A text-entry screen using the system software keyboard (`swkbdInit` /
  `swkbdInputText`), reached from the multiplayer screen. Suggested label:
  "Have an invite code?".
- Send `BS_PKT_ENROL` on submit, then wait for `BS_PKT_ENROL_OK` for **10
  seconds**. That is the server's probation window (`BS_ENROL_WINDOW_MS`); a
  shorter client timeout would give up while the server is still listening.
- On `BS_PKT_ENROL_OK`: continue into the world exactly as a normal join. Do
  not store the code, and do not offer the screen again on later connects —
  the console is on the allowlist now.
- On timeout: show a failure and offer a retry. **A retry means a whole new
  handshake**, not another `BS_PKT_ENROL` on the dead session. The server frees
  the probation session on any wrong code, so the old session id is gone.

## Input handling

Do **not** validate or normalise the code on the console. Send whatever was
typed. The server uppercases it and discards every character outside its
alphabet before hashing, so `9k4b2-hmq7x`, `9K4B2 HMQ7X` and `9K4B2HMQ7X` all
work. Client-side validation could only ever reject something the server would
have accepted.

For reference, not for enforcement: codes are 10 symbols from
`23456789ABCDEFGHJKMNPQRSTVWXYZ` (no 0/O, no 1/I/L, no U), displayed as
`XXXXX-XXXXX`.

## Failure messages worth getting right

The server deliberately gives the console no reason for a failure — a code
that is wrong, expired, burnt, or never armed all look identical from the
outside, so nothing on the wire helps an attacker distinguish them. The
console therefore cannot say *why*. Say something like:

> That code didn't work. Ask for a new one — codes expire after 15 minutes and
> only work once.

which is true in all four cases.

## What the console must NOT do

- Do not retry automatically. Three wrong codes burn the invite for everyone;
  an automatic retry loop would destroy it on one typo.
- Do not send `BS_PKT_ENROL` from an already-established session. The server
  drops the packet and logs it.
- Do not send anything other than `BS_PKT_ENROL` while waiting on probation.
  A well-formed `DATA` packet ends the probation session immediately.

## Testing it

`bsgate-keys invite <label>` on the container arms a code and prints it once.
`bsgate-status` shows the time remaining and, while a console is mid-attempt,
an `enrolling now` line. `journalctl -u bsgate` logs `may attempt enrolment
as '<label>'`, then either `ENROLLED '<label>' key <hex>` or `wrong invite
code from <addr> — N attempt(s) left`.
