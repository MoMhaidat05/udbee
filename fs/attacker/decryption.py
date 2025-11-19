import base64, struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

def decrypt_symmetric(binary_payload, master_key):
    try:
        # [FIX] Do NOT double decode. core.py already decoded the Base32 to bytes.
        # Input 'binary_payload' is bytes.
        
        header_size = struct.calcsize('!HH')
        header = binary_payload[:header_size]
        len_nonce, len_tag = struct.unpack('!HH', header)
        
        # [FIX] Extract the 16-byte Salt
        salt_len = 16
        pos_salt_start = header_size
        pos_nonce_start = pos_salt_start + salt_len
        msg_salt = binary_payload[pos_salt_start:pos_nonce_start]

        # [FIX] Derive the message specific key
        message_key = HKDF(master_key, 32, msg_salt, SHA256)
        
        pos_tag_start = pos_nonce_start + len_nonce
        pos_cipher_start = pos_tag_start + len_tag
        
        nonce = binary_payload[pos_nonce_start:pos_tag_start]
        tag = binary_payload[pos_tag_start:pos_cipher_start]
        ciphertext = binary_payload[pos_cipher_start:]
        
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return {"message": plaintext, "success": True}
        
    except ValueError as e:
        return {"message": f"Tag verification failed {e}", "success": False}
    except Exception as e:
        return {"message": "Failed to decrypt the message", "success": False, "error": str(e)}

def handshake_initiate_parser(binary_payload):
    try:
        victim_ephemeral_pub_pem = binary_payload.decode('utf8')
        return {"victim_eph_pub_pem": victim_ephemeral_pub_pem, "success": True}
    except Exception as e:
        return {"message": f"Handshake init parse failed: {str(e)}", "success": False}