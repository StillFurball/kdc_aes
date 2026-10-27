import json
import os
import secrets
import string
import sys
import threading

from decrypt import decrypt
from encrypt import encrypt
from gcm import AuthenticationError

KEY_LENGTHS = (16, 24, 32)
HANDSHAKE_TIMEOUT = 15
SEPARATOR = "||"

_print_lock = threading.Lock()


class ProtocolError(Exception):
    pass


def say(text=""):
    with _print_lock:
        sys.stdout.write("\r" + text.ljust(2) + "\n> ")
        sys.stdout.flush()


def prompt():
    with _print_lock:
        sys.stdout.write("> ")
        sys.stdout.flush()


def is_printable_ascii(text):
    return all(32 <= ord(ch) < 127 for ch in text)


def key_error(key):
    if not is_printable_ascii(key):
        return "key must use printable ASCII characters only"
    if len(key) not in KEY_LENGTHS:
        return "key must be 16, 24 or 32 characters (AES-128/192/256), got %d" % len(key)
    return None


def ask_key(label):
    while True:
        key = input("%s (16/24/32 ASCII chars): " % label)
        error = key_error(key)
        if error is None:
            return key
        print("  " + error)


def parse_address(text, default_port):
    host, _, port = text.rpartition(":")
    if not host:
        return text, default_port
    return host, int(port)


def env(name, default):
    return os.environ.get(name, default)


def new_nonce():
    return secrets.randbits(64)


def f(nonce):
    return nonce + 1


def random_ascii_key(length):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def join_fields(*fields):
    return SEPARATOR.join(str(field) for field in fields)


def split_fields(text, count):
    fields = text.split(SEPARATOR)
    if len(fields) != count:
        raise ProtocolError("unexpected plaintext format: %r" % text)
    return fields


def seal(key, plaintext):
    nonce = secrets.token_bytes(12)
    ciphertext, tag = encrypt(key.encode("ascii"), nonce, plaintext.encode("ascii"))
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}


def unseal(key, box, description):
    try:
        plaintext = decrypt(
            key.encode("ascii"),
            bytes.fromhex(box["nonce"]),
            bytes.fromhex(box["ciphertext"]),
            bytes.fromhex(box["tag"]),
        )
    except AuthenticationError:
        raise ProtocolError("cannot decrypt %s: tag mismatch (wrong key or tampered data)" % description)
    return plaintext.decode("ascii")


def show_box(box, indent="    "):
    return "\n".join([
        indent + "nonce      : " + box["nonce"],
        indent + "ciphertext : " + box["ciphertext"],
        indent + "tag        : " + box["tag"],
    ])


def expect(message, kind):
    if message.get("type") == "error":
        raise ProtocolError("other side reported: " + message.get("reason", "unknown error"))
    if message.get("type") != kind:
        raise ProtocolError("expected %s, got %s" % (kind, message.get("type")))
    return message


class Channel:
    def __init__(self, sock):
        self.sock = sock
        self.reader = sock.makefile("r", encoding="ascii", newline="\n")

    def send(self, message):
        self.sock.sendall((json.dumps(message) + "\n").encode("ascii"))

    def receive(self):
        line = self.reader.readline()
        if not line:
            raise ConnectionError("connection closed")
        return json.loads(line)

    def send_error(self, reason):
        try:
            self.send({"type": "error", "reason": reason})
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Peer:
    HELP = [
        "/key [new]      show or change my master key (shared with the KDC)",
        "/setks <key>    replace the session key Ks on this side only",
        "/status         show identity, keys and partner",
        "/close          close the current session",
        "/quit           exit",
        "<text>          send <text> to the partner, encrypted with Ks",
    ]

    def __init__(self, name):
        self.name = name
        self.master_key = ask_key("Master key for %s" % name)
        self.channel = None
        self.partner = None
        self.session_key = None

    def commands(self):
        return {
            "/help": self.show_help,
            "/key": self.change_master_key,
            "/setks": self.set_session_key,
            "/status": self.show_status,
            "/close": lambda arg: self.close_session(announce=True),
            "/quit": self.quit,
        }

    def show_help(self, arg=""):
        say("Commands:\n" + "\n".join("  " + line for line in self.HELP))

    def change_master_key(self, arg):
        if not arg:
            say("Master key: %s" % self.master_key)
            return
        error = key_error(arg)
        if error:
            say(error)
            return
        self.master_key = arg
        say("Master key changed to: %s (the KDC must use the same key)" % arg)

    def set_session_key(self, arg):
        if self.channel is None:
            say("No active session")
            return
        error = key_error(arg)
        if error:
            say(error)
            return
        self.session_key = arg
        say("Session key Ks changed locally to: %s" % arg)

    def show_status(self, arg=""):
        say("\n".join([
            "Name        : %s" % self.name,
            "Master key  : %s" % self.master_key,
            "Partner     : %s" % (self.partner or "-"),
            "Session key : %s" % (self.session_key or "-"),
        ]))

    def quit(self, arg=""):
        self.close_session()
        raise SystemExit(0)

    def start_session(self, channel, partner, session_key):
        self.close_session()
        self.channel = channel
        self.partner = partner
        self.session_key = session_key
        threading.Thread(target=self.receive_loop, args=(channel,), daemon=True).start()
        say("=== Secure session with %s established. Ks = %s ===" % (partner, session_key))
        say("Type a message to send it with AES-%d-GCM." % (len(session_key) * 8))

    def close_session(self, announce=False):
        channel, self.channel = self.channel, None
        if channel is not None:
            channel.close()
            if announce:
                say("Session with %s closed" % self.partner)
        elif announce:
            say("No active session")

    def receive_loop(self, channel):
        try:
            while True:
                message = expect(channel.receive(), "message")
                say("[recv] from %s, ciphertext (hex):\n%s" % (self.partner, show_box(message["box"])))
                try:
                    say("    plaintext  : " + unseal(self.session_key, message["box"], "message"))
                except ProtocolError as error:
                    say("    " + str(error))
        except (ConnectionError, OSError, ValueError, ProtocolError):
            pass
        if self.channel is channel:
            self.channel = None
            say("Session with %s ended by the other side" % self.partner)

    def send_message(self, text):
        if self.channel is None:
            say("No active session. Run the key distribution first.")
            return
        if not is_printable_ascii(text):
            say("Plaintext must be printable ASCII")
            return
        box = seal(self.session_key, text)
        try:
            self.channel.send({"type": "message", "box": box})
        except OSError as error:
            say("Send failed: %s" % error)
            self.close_session()
            return
        say("[send] to %s\n    plaintext  : %s\n%s" % (self.partner, text, show_box(box)))

    def run_console(self):
        self.show_help()
        handlers = self.commands()
        while True:
            try:
                line = input().strip()
            except (EOFError, KeyboardInterrupt):
                self.quit()
            if not line:
                prompt()
            elif line.startswith("/"):
                command, _, arg = line.partition(" ")
                handler = handlers.get(command)
                if handler is None:
                    say("Unknown command. Type /help")
                else:
                    handler(arg.strip())
            else:
                self.send_message(line)
