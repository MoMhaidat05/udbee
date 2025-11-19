import base64, struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128

def encrypt_symmetric(message, shared_aes_key):
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        elif not isinstance(message, bytes):
            message = str(message).encode("utf-8")
            
        cipher = AES.new(shared_aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        header = struct.pack('!HH', len(cipher.nonce), len(tag))
        
        binary_payload = header + cipher.nonce + tag + ciphertext
        
        payload_text = base64.b32hexencode(binary_payload).rstrip(b'=').decode('utf8')
        
        return {"message": payload_text, "success": True}
    except Exception as e:
        print('failed decryption\n'+e)
        return {"message": "Failed to encrypt the message", "success": False, "error": str(e)}

def derive_static_session_key(victim_ephemeral_pub_pem, attacker_static_privkey):
    try:
        victim_eph_pubkey = ECC.import_key(victim_ephemeral_pub_pem)
        
        shared_point = attacker_static_privkey.d * victim_eph_pubkey.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
        
        aes_key = SHAKE128.new(shared_secret).read(32)

        return {"aes_key": aes_key, "success": True}
        
    except Exception as e:
        return {"message": f"Handshake key derivation failed: {str(e)}", "success": False}