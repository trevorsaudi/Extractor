import struct

def fnv1a_hash(string):
    """Computes the FNV-1a hash, as seen in sub_4453F3."""
    hash = 0x811C9DC5  # Initial seed (-2128831035 in hex)
    fnv_prime = 0x01000193  # 16777619

    for char in string:
        hash ^= ord(char)  # XOR each character
        hash *= fnv_prime  # Multiply by prime
        hash &= 0xFFFFFFFF  # Ensure 32-bit hash
    return hash

# Malware-resolved API hash value
target_hash = 0xB0327E93

# Expanded API list covering kernel32.dll, ntdll.dll, user32.dll, advapi32.dll, shell32.dll
api_list = [
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    "VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc", "HeapFree",
    "CreateProcessA", "CreateProcessW", "WinExec", "TerminateProcess", "GetSystemMetrics",
   
]

# Brute-force the API name
for api in api_list:
    if fnv1a_hash(api) == target_hash:
        print(f"✅ API Found: {api} -> {hex(target_hash)}")
        break

