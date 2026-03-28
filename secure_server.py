import socket
import os
import struct
import fcntl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import os

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

SERVER_PORT = 5555

def generate_keys():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()
    return private, public


def serialize_pub(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


def deserialize_pub(data):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), data
    )


def derive_key(private, peer_public):
    shared = private.exchange(ec.ECDH(), peer_public)

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pyvpn"
    ).derive(shared)

    return key
def encrypt_packet(aes, data):
    nonce = os.urandom(12)
    enc = aes.encrypt(nonce, data, None)
    return nonce + enc


def decrypt_packet(aes, data):
    nonce = data[:12]
    ct = data[12:]
    return aes.decrypt(nonce, ct, None)
def create_tun():
    tun = os.open("/dev/net/tun", os.O_RDWR)

    ifr = struct.pack("16sH", b"tun0", IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)

    os.system("ip addr add 10.0.0.1/24 dev tun0")
    os.system("ip link set tun0 up")
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

    return tun


def main():
    tun = create_tun()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SERVER_PORT))

    client = None

    print("VPN server listening")

    while True:
        r, _, _ = select.select([sock, tun], [], [])

        for fd in r:

            if fd == sock:
                data, addr = sock.recvfrom(65535)
                if client is None:
                	client = addr
                	priv, pub = generate_keys()
                	client_pub = deserialize_pub(data)
                	sock.sendto(serialize_pub(pub), client)
                	shared_key = derive_key(priv, client_pub)
                	aes = AESGCM(shared_key)
                	print("Secure tunnel established")
                	continue
                data = decrypt_packet(aes, data)
                os.write(tun, data)

            if fd == tun:
                pkt = os.read(tun, 65535)
                if client:
                    enc = encrypt_packet(aes, pkt)
                    sock.sendto(enc, client)


if __name__ == "__main__":
    import select
    main()
