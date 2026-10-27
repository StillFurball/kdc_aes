import argparse
import socket
import threading

from common import (
    HANDSHAKE_TIMEOUT, Channel, Peer, ProtocolError, env, expect, f, new_nonce,
    say, seal, show_box, split_fields, unseal,
)


class Bob(Peer):
    def __init__(self, name, host, port):
        super().__init__(name)
        self.address = (host, port)

    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(self.address)
        server.listen()
        say("%s listening on %s:%d, waiting for step 3" % ((self.name,) + self.address))
        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        conn.settimeout(HANDSHAKE_TIMEOUT)
        channel = Channel(conn)
        try:
            session_key, initiator = self.respond(channel, addr)
        except ProtocolError as error:
            say("Key distribution failed: %s" % error)
            channel.send_error(str(error))
            channel.close()
            return
        except (ConnectionError, OSError, ValueError) as error:
            say("Connection problem with %s: %s" % (addr[0], error))
            channel.close()
            return
        conn.settimeout(None)
        self.start_session(channel, initiator, session_key)

    def respond(self, channel, addr):
        step3 = expect(channel.receive(), "step3")
        say("[step 3] <- %s   E(Kb, [Ks||IDA]):\n%s" % (addr[0], show_box(step3["box"])))
        plaintext = unseal(self.master_key, step3["box"], "E(Kb, [Ks||IDA])")
        session_key, initiator = split_fields(plaintext, 2)
        say("  decrypted with Kb: %s -> Ks = %s, IDA = %s" % (plaintext, session_key, initiator))

        n2 = new_nonce()
        box = seal(session_key, str(n2))
        channel.send({"type": "step4", "box": box})
        say("[step 4] -> %s   E(Ks, N2) with N2 = %d:\n%s" % (initiator, n2, show_box(box)))

        step5 = expect(channel.receive(), "step5")
        say("[step 5] <- %s   E(Ks, f(N2)):\n%s" % (initiator, show_box(step5["box"])))
        answer = int(unseal(session_key, step5["box"], "E(Ks, f(N2))"))
        if answer != f(n2):
            raise ProtocolError("f(N2) check failed: expected %d, got %d" % (f(n2), answer))
        say("  decrypted with Ks: f(N2) = %d = N2 + 1 -> %s is authenticated" % (answer, initiator))
        return session_key, initiator


def main():
    parser = argparse.ArgumentParser(description="Bob: responder of the key distribution")
    parser.add_argument("--name", default=env("NODE_NAME", "Bob"))
    parser.add_argument("--host", default=env("LISTEN_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(env("LISTEN_PORT", "6000")))
    args = parser.parse_args()

    bob = Bob(args.name, args.host, args.port)
    threading.Thread(target=bob.listen, daemon=True).start()
    bob.run_console()


if __name__ == "__main__":
    main()
