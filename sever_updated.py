import asyncio
import websockets
import json
import base64
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

clients = {}  # websocket: {"sender": str, "pubkey": RSA key}

# Tải khóa riêng của server để ký
with open("server_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def encrypt_aes(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode()))

def rsa_encrypt(data, pubkey):
    cipher_rsa = PKCS1_OAEP.new(pubkey)
    return cipher_rsa.encrypt(data)

def rsa_sign(data, privkey):
    h = SHA256.new(data)
    return pkcs1_15.new(privkey).sign(h)

async def handler(websocket):
    print("Client connected.")
    try:
        # 1. Handshake: Nhận khóa công khai từ client
        handshake_msg = await websocket.recv()
        handshake_data = json.loads(handshake_msg)
        if handshake_data.get("type") != "handshake" or "public_key" not in handshake_data:
            await websocket.send(json.dumps({"error": "Handshake required"}))
            return

        sender_name = handshake_data.get("sender", "unknown")
        client_pubkey = RSA.import_key(base64.b64decode(handshake_data["public_key"]))
        clients[websocket] = {"sender": sender_name, "pubkey": client_pubkey}
        print(f"Handshake thành công với {sender_name}")

        await websocket.send(json.dumps({"status": "handshake_ok"}))

        # 2. Nhận/gửi tin nhắn
        async for msg in websocket:
            data = json.loads(msg)
            sender = data["sender"]
            message = data["message"]

            # Sinh AES-256 key và IV mỗi lần gửi
            aes_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            ciphertext = encrypt_aes(message, aes_key, iv)

            # Hash toàn vẹn
            hash_digest = hashlib.sha256(iv + ciphertext).hexdigest()

            # Ký metadata
            metadata = f"{sender}-session01".encode()
            signature = rsa_sign(metadata, private_key)

            # Mã hóa AES key bằng RSA của client nhận
            encrypted_key = rsa_encrypt(aes_key, client_pubkey)

            payload = {
                "sender": sender,
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "hash": hash_digest,
                "signature": base64.b64encode(signature).decode(),
                "key": base64.b64encode(encrypted_key).decode(),
                # "plaintext": message  # Không nên gửi plaintext trong thực tế!
            }

            # Gửi cho tất cả client khác (hoặc chỉ gửi lại cho chính client này nếu muốn)
            for client_ws in clients:
                await client_ws.send(json.dumps(payload))

    except Exception as e:
        print("Lỗi:", e)
    finally:
        clients.pop(websocket, None)
        print("Client disconnected.")

SERVER_HOST = "192.168.0.104"
SERVER_PORT = 8765

async def main():
    async with websockets.serve(handler, SERVER_HOST, SERVER_PORT):
        print(f"Server chạy tại ws://{SERVER_HOST}:{SERVER_PORT}")
        await asyncio.Future()

asyncio.run(main())
