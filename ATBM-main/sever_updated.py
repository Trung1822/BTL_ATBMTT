import asyncio
import websockets
import json
import base64
import hashlib
from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

clients = set()
connected_senders = set()

with open("server_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

with open("client_public.pem", "rb") as f:
    client_pubkey = RSA.import_key(f.read())

def pad(data):
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len]) * pad_len

def encrypt_3des(plaintext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode()))

def rsa_encrypt(data, pubkey):
    cipher_rsa = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)
    return cipher_rsa.encrypt(data)

def rsa_sign(data, privkey):
    h = SHA256.new(data)
    return pkcs1_15.new(privkey).sign(h)

async def handler(websocket):
    clients.add(websocket)
    sender_name = None
    print("Client connected.")
    try:
        async for msg in websocket:
            data = json.loads(msg)
            if data.get("type") == "ACK":
                print(f"ACK từ {data.get('sender')}")
                continue
            if data.get("type") == "NACK":
                print(f"NACK từ {data.get('sender')}: {data.get('reason')}")
                continue

            sender = data["sender"]
            message = data["message"]

            if sender_name is None:
                sender_name = sender
                connected_senders.add(sender_name)
                print("Senders đang kết nối:", list(connected_senders))

            des3_key = DES3.adjust_key_parity(get_random_bytes(24))
            iv = get_random_bytes(8)
            ciphertext = encrypt_3des(message, des3_key, iv)

            hash_digest = hashlib.sha256(iv + ciphertext).hexdigest()
            metadata = f"{sender}-session01".encode()
            signature = rsa_sign(metadata, private_key)
            encrypted_key = rsa_encrypt(des3_key, client_pubkey)

            payload = {
                "sender": sender,
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "hash": hash_digest,
                "signature": base64.b64encode(signature).decode(),
                "key": base64.b64encode(encrypted_key).decode(),
                "des3_key_clear": base64.b64encode(des3_key).decode()  # Dòng này phải có!
            }

            for client in clients:
                await client.send(json.dumps(payload))

    except Exception as e:
        print("Lỗi:", e)
    finally:
        clients.remove(websocket)
        if sender_name:
            connected_senders.discard(sender_name)
            print("Senders đang kết nối:", list(connected_senders))
        print("Client disconnected.")

SERVER_HOST = "172.16.3.75"
SERVER_PORT = 8765

async def main():
    async with websockets.serve(handler, SERVER_HOST, SERVER_PORT):
        print(f"Server chạy tại ws://{SERVER_HOST}:{SERVER_PORT}")
        await asyncio.Future()

asyncio.run(main())
