import ctypes
import socket
import struct
import threading
import subprocess
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import os


SERVER_IP = "SERVER_IP"
SERVER_PORT = 5555
TUN_IP = "10.0.0.2"
PEER_IP = "10.0.0.1"

WINTUN_MAX_PACKET_SIZE = 0xFFFF
WINTUN_RING_CAPACITY = 0x400000

wintun = ctypes.WinDLL("full/path/to/wintun.dll")
# Wintun types
WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
WINTUN_SESSION_HANDLE = ctypes.c_void_p

# API prototypes
wintun.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE
wintun.WintunCreateAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]

wintun.WintunStartSession.restype = WINTUN_SESSION_HANDLE
wintun.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, ctypes.c_uint32]

wintun.WintunReceivePacket.restype = ctypes.c_void_p
wintun.WintunReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(ctypes.c_uint32)]

wintun.WintunReleaseReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.c_void_p]

wintun.WintunAllocateSendPacket.restype = ctypes.c_void_p
wintun.WintunAllocateSendPacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.c_uint32]

wintun.WintunSendPacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.c_void_p]

def encrypt_packet(aes, data):
    nonce = os.urandom(12)
    enc = aes.encrypt(nonce, data, None)
    return nonce + enc


def decrypt_packet(aes, data):
    nonce = data[:12]
    ct = data[12:]
    
    return aes.decrypt(nonce, ct, None)
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

def create_adapter():
    adapter = wintun.WintunCreateAdapter("PyVPN", "Wintun", None)
    if not adapter:
        raise RuntimeError("Failed to create adapter")
    return adapter


def configure_interface():
    subprocess.run([
        "netsh", "interface", "ip", "set", "address",
        "name=PyVPN",
        "static", TUN_IP, "255.255.255.0"
    ], check=True)

    subprocess.run([
        "route", "add", PEER_IP, "mask", "255.255.255.255", TUN_IP
    ], check=False)


def start_session(adapter):
    session = wintun.WintunStartSession(adapter, WINTUN_RING_CAPACITY)
    if not session:
        raise RuntimeError("Session failed")
    return session


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((SERVER_IP, SERVER_PORT))

priv, pub = generate_keys()

sock.send(serialize_pub(pub))

server_pub_bytes = sock.recv(1024)
server_pub = deserialize_pub(server_pub_bytes)

shared_key = derive_key(priv, server_pub)
aes = AESGCM(shared_key)

print("Secure tunnel established")
def tun_to_udp(session):
    """Read packets from Wintun -> send to server"""

    size = ctypes.c_uint32()

    while True:
        pkt = wintun.WintunReceivePacket(session, ctypes.byref(size))

        if not pkt:
            time.sleep(0.001)
            continue

        try:
            buf = ctypes.string_at(pkt, size.value)
            enc = encrypt_packet(aes, buf)
            sock.send(enc)
        finally:
            wintun.WintunReleaseReceivePacket(session, pkt)


def udp_to_tun(session):
    """Receive UDP packets -> inject into Wintun"""

    while True:
        data = sock.recv(65535)
        data = decrypt_packet(aes, data)

        pkt = wintun.WintunAllocateSendPacket(session, len(data))
        if not pkt:
            continue

        ctypes.memmove(pkt, data, len(data))
        wintun.WintunSendPacket(session, pkt)


def main():
    adapter = create_adapter()
    configure_interface()

    session = start_session(adapter)

    t1 = threading.Thread(target=tun_to_udp, args=(session,), daemon=True)
    t2 = threading.Thread(target=udp_to_tun, args=(session,), daemon=True)

    t1.start()
    t2.start()

    print("VPN client running")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
