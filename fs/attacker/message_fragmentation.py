import random


def fragment_message(message, chunk_size):
    """
    Break a message into smaller pieces for DNS transmission.
    Each chunk includes metadata so the victim can reassemble it correctly.
    """
    message = str(message)
    chunks = []
    
    # Generate a unique ID for this message - all chunks will share it
    session_id = random.randint(0,65535)
    
    # Calculate how many chunks we need for this message
    total = (len(message) + chunk_size - 1) // chunk_size
    
    # Split message into chunks and add metadata
    for i in range(total):
        # Extract the actual chunk data
        part = message[i*chunk_size : (i+1)*chunk_size]
        
        # Build chunk with metadata: session_id|chunk_number|total_chunks|data
        chunk = f"{session_id}|{i}|{total}|{part}"
        chunks.append(chunk)
    
    return chunks