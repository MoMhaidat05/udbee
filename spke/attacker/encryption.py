import base64, struct
from Crypto.Cipher import AES

def encrypt_message(message, shared_aes_key):
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        elif not isinstance(message, bytes):
            message = str(message).encode("utf-8")
            
        cipher = AES.new(shared_aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        header = struct.pack(
            '!HH', 
            len(cipher.nonce), 
            len(tag)
        )
        
        binary_payload = header + cipher.nonce + tag + ciphertext
        payload_text = base64.b32hexencode(binary_payload).rstrip(b'=').decode('utf8')
        
        return {"message": payload_text, "success": True}
    except Exception as e:
        return {"message": "Failed to encrypt the message", "success": False, "error": str(e)}