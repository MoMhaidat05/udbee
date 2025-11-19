import base64, struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128

def decrypt_symmetric(binary_payload, shared_aes_key):
    """Decrypt a message using AES-GCM with the established shared key"""
    try:
        # Parse the header to extract lengths of nonce and tag
        header_size = struct.calcsize('!HH')
        header = binary_payload[:header_size]
        len_nonce, len_tag = struct.unpack('!HH', header)
        
        # Calculate where each component starts in the payload
        pos_nonce_start = header_size
        pos_tag_start = pos_nonce_start + len_nonce
        pos_cipher_start = pos_tag_start + len_tag
        
        # Extract nonce, tag, and ciphertext from the payload
        nonce = binary_payload[pos_nonce_start:pos_tag_start]
        tag = binary_payload[pos_tag_start:pos_cipher_start]
        ciphertext = binary_payload[pos_cipher_start:]
        
        # Decrypt with AES-GCM (verifies authenticity tag automatically)
        cipher = AES.new(shared_aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return {"message": plaintext, "success": True}
        
    except ValueError as e:
        # Tag verification failed means the message was tampered with
        return {"message": f"Tag verification failed {e}", "success": False}
    except Exception as e:
        return {"message": "Failed to decrypt the message", "success": False, "error": str(e)}

def handshake_initiate_parser(binary_payload):
    """Extract victim's ephemeral public key from the handshake initiation message"""
    try:
        # Victim sends their ephemeral public key in PEM format
        victim_ephemeral_pub_pem = binary_payload.decode('utf8')
        
        return {"victim_eph_pub_pem": victim_ephemeral_pub_pem, "success": True}
    except Exception as e:
        return {"message": f"Handshake init parse failed: {str(e)}", "success": False}