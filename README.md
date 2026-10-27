# KDC + AES-GCM (Key Distribution Scenario)

Three programs on three IP addresses: **KDC**, **Alice** (initiator) and **Bob** (responder).
They run the 5-step key distribution from the slide (Security 07, slide 13), then Alice and Bob
chat both ways with **AES-GCM** using the session key **Ks**.
AES and GCM are written by hand in pure Python. Nothing outside the standard library is used.

## Files

| File | Contents |
|---|---|
| `s_box.py` | AES S-box table, `sub_bytes` |
| `mix_column.py` | `xtime`, `mix_columns` (multiplication in GF(2^8)) |
| `aes.py` | key expansion, `shift_rows`, `add_round_key`, AES block encryption (128/192/256) |
| `gcm.py` | GCM parts: `gf_mult` (GF(2^128)), `ghash`, `inc32`, `gctr` (counter mode), tag |
| `encrypt.py` / `decrypt.py` | AES-GCM encrypt (ciphertext + tag) / decrypt (check tag first) |
| `common.py` | TCP messages (JSON, one per line), `seal`/`unseal`, key checks, shared chat console |
| `kdc.py` | KDC: stores master keys, answers step 1 with step 2 |
| `alice.py` | initiator: steps 1, 2, 3, 5 |
| `bob.py` | responder: steps 3, 4, 5 |
| `test_aes.py` | checks AES/GCM against official NIST test vectors |
| `Dockerfile`, `compose.yaml` | 3 containers with fixed IPs |
| `capture.bat` | live Wireshark capture from a container |

## The 5 steps in the code

| Step | Direction | Sent on the network | Where |
|---|---|---|---|
| 1 | Alice -> KDC | `IDA, IDB, N1` (plaintext) | `Alice.request_session_key` |
| 2 | KDC -> Alice | `E(Ka, [Ks‖IDA‖IDB‖N1])` and `E(Kb, [Ks‖IDA])` | `KDC.answer_request` |
| 3 | Alice -> Bob | `E(Kb, [Ks‖IDA])`, forwarded unchanged | `Alice.authenticate` / `Bob.respond` |
| 4 | Bob -> Alice | `E(Ks, N2)` | `Bob.respond` |
| 5 | Alice -> Bob | `E(Ks, f(N2))`, where f(N2) = N2 + 1 | `Alice.authenticate` / `Bob.respond` |
| chat | both ways | `E(Ks, message)` | `Peer.send_message` / `Peer.receive_loop` |

Every `E(key, ...)` is AES-GCM. It is sent as `nonce` (12 bytes), `ciphertext` and `tag` (16 bytes), all in hex.
A fresh random nonce is used for every message.
Keys and plaintext are ASCII. Key length decides the AES version: 16 = AES-128, 24 = AES-192, 32 = AES-256.

## Run with Docker (3 IPs)

| Container | IP | Port |
|---|---|---|
| kdc | 172.28.0.10 | 5000 |
| alice | 172.28.0.11 | - |
| bob | 172.28.0.12 | 6000 |

Once, from this folder (Docker Desktop running):

```
docker compose up -d --build
```

Open 3 terminals:

```
docker exec -it kdc   python kdc.py
docker exec -it bob   python bob.py
docker exec -it alice python alice.py
```

1. Bob and Alice each ask for their master key at start-up.
2. On the KDC, register the same keys: `/set Alice <Ka>` and `/set Bob <Kb>`.
3. On Alice: `/connect`. Steps 1–5 run and are printed on all three screens.
4. Type text on Alice or on Bob to send it encrypted.

The folder is mounted into the containers, so code edits apply on the next program start without a rebuild.
To stop everything: `docker compose down`.

## Run locally (1 PC, for development)

```
python kdc.py
python bob.py
python alice.py
```

Defaults are `127.0.0.1`, KDC port 5000 and Bob port 6000. Other addresses:
`python alice.py --kdc 192.168.1.10:5000 --peer Bob@192.168.1.12:6000`.

## Commands

KDC: `/set <ID> <key>`, `/del <ID>`, `/list`, `/kslen 16|24|32`, `/quit`

Alice and Bob:
- `/key [new]`: show or change own master key
- `/setks <key>`: change Ks on this side only
- `/status`, `/close`, `/quit`
- any other text: sent encrypted

Alice only: `/connect [ID host:port]` runs steps 1–5 again, which also gives a new Ks.

All keys can be changed while the programs run, with no restart.

## Wireshark

**Live, Docker:** in Command Prompt, from this folder, run `capture.bat` (or `capture.bat bob`).
It runs tcpdump inside the container and streams it into Wireshark on Windows.
Capturing on `alice` shows every step, because Alice takes part in all of them.
To save a file instead:

```
docker exec alice tcpdump -i eth0 -w /app/captures/demo.pcap
```

Stop it with Ctrl+C, then open `captures\demo.pcap`.

**Local run:** capture on *Adapter for loopback traffic capture*.

Display filter:

```
(tcp.port == 5000 || tcp.port == 6000) && tcp.len > 0
```

Right-click a packet and choose **Follow > TCP Stream** to read the messages:
- **step1:** readable. IDs and N1 are plaintext on the slide too.
- **step2 to step5 and chat:** only hex nonce, ciphertext and tag. No key or chat text appears on the wire.

## Demo test cases

| Test | How | Expected |
|---|---|---|
| Normal run | `/connect`, then chat both ways | session established, messages decrypt |
| Wrong Ka | Alice `/key` with another key, `/connect` | Alice: cannot decrypt E(Ka, ...) at step 2 |
| Wrong Kb | KDC `/set Bob <other key>`, Alice `/connect` | Bob: cannot decrypt step 3; Alice told |
| Unknown ID | Alice `/connect Carol 172.28.0.12:6000` | KDC rejects step 1 |
| New session key | Alice `/connect` again | new Ks on both sides |
| AES-128 / 256 | KDC `/kslen 16` or `/kslen 32`, then `/connect` | Ks length changes |
| Key mismatch | Alice `/setks <other 16 chars>`, send text | Bob: tag mismatch, message rejected |
| AES correctness | `python test_aes.py` | all NIST vectors OK |

## Notes

- GCM only uses the AES *encryption* direction. Decryption makes the same keystream from the counter and XORs it again,
  so no inverse S-box or InvMixColumns is needed.
- The tag is checked before anything is decrypted. A wrong key or one changed bit causes rejection.
- Known weakness of this protocol (Denning–Sacco): if an old Ks ever leaks, an attacker can replay the old step 3 to Bob,
  because step 3 has no timestamp. Kerberos fixes this with timestamps.
