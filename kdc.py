import argparse
import socket
import threading

from common import (
    HANDSHAKE_TIMEOUT, Channel, ProtocolError, env, expect, join_fields, key_error,
    prompt, random_ascii_key, say, seal, show_box,
)

HELP = [
    "/set <ID> <key>   register or change the master key of a user",
    "/del <ID>         remove a user",
    "/list             show registered users and master keys",
    "/kslen <n>        session key length: 16, 24 or 32 (AES-128/192/256)",
    "/quit             stop the KDC",
]


class KDC:
    def __init__(self, host, port):
        self.address = (host, port)
        self.master_keys = {}
        self.session_key_length = 32

    def serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(self.address)
        server.listen()
        say("KDC listening on %s:%d" % self.address)
        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        conn.settimeout(HANDSHAKE_TIMEOUT)
        channel = Channel(conn)
        try:
            self.answer_request(channel, addr)
        except ProtocolError as error:
            say("  request rejected: %s" % error)
            channel.send_error(str(error))
        except (ConnectionError, OSError, ValueError) as error:
            say("  connection problem with %s: %s" % (addr[0], error))
        finally:
            channel.close()

    def answer_request(self, channel, addr):
        request = expect(channel.receive(), "step1")
        ida, idb, n1 = request["ida"], request["idb"], request["n1"]
        say("[step 1] <- %s   IDA=%s  IDB=%s  N1=%s   (plaintext)" % (addr[0], ida, idb, n1))
        for identity in (ida, idb):
            if identity not in self.master_keys:
                raise ProtocolError("identity '%s' is not registered at the KDC" % identity)

        session_key = random_ascii_key(self.session_key_length)
        say("  generated session key Ks = %s" % session_key)
        box_a = seal(self.master_keys[ida], join_fields(session_key, ida, idb, n1))
        box_b = seal(self.master_keys[idb], join_fields(session_key, ida))
        channel.send({"type": "step2", "box_a": box_a, "box_b": box_b})
        say("[step 2] -> %s\n  E(K_%s, [Ks||IDA||IDB||N1]):\n%s\n  E(K_%s, [Ks||IDA]):\n%s"
            % (ida, ida, show_box(box_a), idb, show_box(box_b)))

    def set_key(self, arg):
        identity, _, key = arg.partition(" ")
        if not identity.isalnum():
            say("Usage: /set <ID> <key>   (ID: letters and digits only)")
            return
        error = key_error(key)
        if error:
            say(error)
            return
        self.master_keys[identity] = key
        say("Master key for %s set to: %s" % (identity, key))

    def delete_key(self, arg):
        if self.master_keys.pop(arg, None) is None:
            say("No such user: %s" % arg)
        else:
            say("Removed %s" % arg)

    def list_keys(self, arg=""):
        if not self.master_keys:
            say("No users registered yet. Use /set <ID> <key>")
            return
        lines = ["  %-10s %s" % (identity, key) for identity, key in self.master_keys.items()]
        say("Registered users (Ks length %d):\n%s" % (self.session_key_length, "\n".join(lines)))

    def set_session_key_length(self, arg):
        if arg not in ("16", "24", "32"):
            say("Usage: /kslen 16|24|32")
            return
        self.session_key_length = int(arg)
        say("New session keys will be %s characters (AES-%d)" % (arg, int(arg) * 8))

    def run_console(self):
        handlers = {
            "/set": self.set_key,
            "/del": self.delete_key,
            "/list": self.list_keys,
            "/kslen": self.set_session_key_length,
            "/help": lambda arg: say("Commands:\n" + "\n".join("  " + line for line in HELP)),
        }
        handlers["/help"]("")
        while True:
            try:
                line = input().strip()
            except (EOFError, KeyboardInterrupt):
                break
            command, _, arg = line.partition(" ")
            if command == "/quit":
                break
            if not line:
                prompt()
            elif command in handlers:
                handlers[command](arg.strip())
            else:
                say("Unknown command. Type /help")


def main():
    parser = argparse.ArgumentParser(description="Key Distribution Center")
    parser.add_argument("--host", default=env("KDC_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(env("KDC_PORT", "5000")))
    args = parser.parse_args()

    kdc = KDC(args.host, args.port)
    threading.Thread(target=kdc.serve, daemon=True).start()
    kdc.run_console()


if __name__ == "__main__":
    main()
