import pefile
import base64
import re

def xor_decrypt(data, key):
    """Decrypt data using XOR with the given key."""
    decrypted = bytearray()
    key_length = len(key)
    for i in range(len(data)):
        decrypted_byte = data[i] ^ ord(key[i % key_length])
        decrypted.append(decrypted_byte)
    return decrypted

def find_base64_strings(pe):
    """Search for Base64-encoded strings in the PE file."""
    base64_pattern = re.compile(
        rb'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    )
    base64_strings = set()

    # Iterate through all sections of the PE file
    for section in pe.sections:
        data = section.get_data()
        matches = base64_pattern.findall(data)
        for match in matches:
            # Filter out short strings (likely false positives)
            if len(match) >= 8:  # Minimum length for meaningful Base64
                base64_strings.add(match.decode('utf-8', errors='ignore'))

    return base64_strings

def decode_and_decrypt(base64_data, xor_key):
    """Decode Base64 and decrypt using XOR."""
    try:
        decoded_data = base64.b64decode(base64_data)
        decrypted_data = xor_decrypt(decoded_data, xor_key)
        return decrypted_data.decode('utf-8', errors='ignore')
    except Exception as e:
        return None  # Return None if decoding fails

def process_pe_file(file_path, xor_key, output_file="decrypted_strings.txt"):
    """Process the PE file to extract, decode, and decrypt Base64 data."""
    pe = pefile.PE(file_path)
    base64_strings = find_base64_strings(pe)

    print(f"Found {len(base64_strings)} potential Base64 strings.")

    with open(output_file, "w", encoding="utf-8") as f:
        for idx, b64_str in enumerate(base64_strings, 1):
            print(f"\nString {idx}: {b64_str}")
            decrypted = decode_and_decrypt(b64_str, xor_key)

            if decrypted:
                print(f"Decrypted: {decrypted}")
                f.write(f"Decoded {idx}:\n{decrypted}\n{'='*40}\n")
            else:
                print("Failed to decode/decrypt.")

    print(f"\n✅ Decrypted strings saved to {output_file}")

# Example usage
if __name__ == "__main__":
    file_path = "new-test.exe" # Replace with your PE file path
    xor_key = "1234niwef"  # Replace with the actual XOR key
    process_pe_file(file_path, xor_key)

