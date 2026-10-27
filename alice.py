import argparse
import socket

from common import (
    HANDSHAKE_TIMEOUT, Channel, Peer, ProtocolError, env, expect, f, new_nonce,
    parse_address, say, seal, show_box, split_fields, unseal,
)


class Alice(Peer):
    HELP = ["/connect [ID host:port]  run key distribution steps 1-5 with a partner"] + Peer.HELP

    def __init__(self, name, kdc_address, partner, partner_address):
        super().__init__(name)
        self.kdc_address = kdc_address
        self.default_partner = (partner, partner_address)

    def commands(self):
        handlers = super().commands()
        handlers["/connect"] = self.connect
        return handlers

    def connect(self, arg):
        partner, address = self.default_partner
        if arg:
            partner, _, address_text = arg.partition(" ")
            address = parse_address(address_text, 6000) if address_text else address
        try:
            session_key, ticket = self.request_session_key(partner)
            channel = self.authenticate(partner, address, session_key, ticket)
        except (ProtocolError, ConnectionError, OSError, ValueError) as error:
            say("Key distribution failed: %s" % error)
            return
        self.start_session(channel, partner, session_key)

    def request_session_key(self, partner):
        n1 = new_nonce()
        with socket.create_connection(self.kdc_address, timeout=HANDSHAKE_TIMEOUT) as sock:
            channel = Channel(sock)
            channel.send({"type": "step1", "ida": self.name, "idb": partner, "n1": n1})
            say("[step 1] -> KDC %s:%d   IDA=%s  IDB=%s  N1=%d   (plaintext)"
                % (self.kdc_address + (self.name, partner, n1)))
            reply = expect(channel.receive(), "step2")

        say("[step 2] <- KDC\n  E(Ka, [Ks||IDA||IDB||N1]):\n%s\n  E(Kb, [Ks||IDA])  (for %s, %s cannot open it):\n%s"
            % (show_box(reply["box_a"]), partner, self.name, show_box(reply["box_b"])))
        plaintext = unseal(self.master_key, reply["box_a"], "E(Ka, ...) from the KDC")
        session_key, ida, idb, echoed_n1 = split_fields(plaintext, 4)
        say("  decrypted with Ka: %s" % plaintext)
        if ida != self.name or idb != partner or echoed_n1 != str(n1):
            raise ProtocolError("KDC reply does not match this request (possible replay)")
        say("  IDs and N1 match the request -> reply is fresh, Ks = %s" % session_key)
        return session_key, reply["box_b"]

    def authenticate(self, partner, address, session_key, ticket):
        sock = socket.create_connection(address, timeout=HANDSHAKE_TIMEOUT)
        channel = Channel(sock)
        try:
            channel.send({"type": "step3", "box": ticket})
            say("[step 3] -> %s %s:%d   forward E(Kb, [Ks||IDA]) unchanged" % ((partner,) + address))

            step4 = expect(channel.receive(), "step4")
            say("[step 4] <- %s   E(Ks, N2):\n%s" % (partner, show_box(step4["box"])))
            n2 = int(unseal(session_key, step4["box"], "E(Ks, N2)"))
            say("  decrypted with Ks: N2 = %d" % n2)

            box = seal(session_key, str(f(n2)))
            channel.send({"type": "step5", "box": box})
            say("[step 5] -> %s   E(Ks, f(N2)) with f(N2) = N2 + 1 = %d:\n%s" % (partner, f(n2), show_box(box)))
        except Exception:
            channel.close()
            raise
        sock.settimeout(None)
        return channel


def main():
    parser = argparse.ArgumentParser(description="Alice: initiator of the key distribution")
    parser.add_argument("--name", default=env("NODE_NAME", "Alice"))
    parser.add_argument("--kdc", default=env("KDC_ADDR", "127.0.0.1:5000"))
    parser.add_argument("--peer", default=env("PEER", "Bob@127.0.0.1:6000"),
                        help="partner as ID@host:port")
    args = parser.parse_args()

    partner, _, partner_address = args.peer.partition("@")
    alice = Alice(args.name, parse_address(args.kdc, 5000), partner, parse_address(partner_address, 6000))
    alice.run_console()


if __name__ == "__main__":
    main()
