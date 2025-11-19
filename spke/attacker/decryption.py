import base64, struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128

def decrypt_message(binary_payload, attacker_static_privkey):
    """
    Decrypt a message using ECDH key exchange and AES-GCM encryption.
    The payload contains: victim's ephemeral public key, nonce, auth tag, and encrypted message.
    """
    try:
        # Parse the header to get lengths of each component
        header_size = struct.calcsize('!HHH')
        header = binary_payload[:header_size]
        len_key, len_nonce, len_tag = struct.unpack('!HHH', header)
        
        # Calculate where each component starts in the binary payload
        pos_key_start = header_size
        pos_nonce_start = pos_key_start + len_key
        pos_tag_start = pos_nonce_start + len_nonce
        pos_cipher_start = pos_tag_start + len_tag
        
        # Extract each component from the payload
        victim_pub_pem = binary_payload[pos_key_start:pos_nonce_start]
        nonce = binary_payload[pos_nonce_start:pos_tag_start]
        tag = binary_payload[pos_tag_start:pos_cipher_start]
        ciphertext = binary_payload[pos_cipher_start:]
        
        # Import victim's ephemeral public key from PEM format
        victim_ephemeral_pubkey = ECC.import_key(victim_pub_pem)
        
        # Perform ECDH: multiply our private key with victim's public key to get shared point
        shared_point = attacker_static_privkey.d * victim_ephemeral_pubkey.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
        
        # Derive AES key from shared secret using SHAKE128 hash
        aes_key = SHAKE128.new(shared_secret).read(32)
        
        # Decrypt using AES-GCM (includes authentication)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Return decrypted message along with the shared key for future use
        return {"message": plaintext, "shared_key": aes_key, "success": True}
        
    except ValueError:
        # Tag verification failed means the message was tampered with
        return {"message": "Tag verification failed", "success": False}
    except Exception as e:
        # Catch any other decryption errors
        return {"message": f"Failed to decrypt the message: {str(e)}", "success": False}