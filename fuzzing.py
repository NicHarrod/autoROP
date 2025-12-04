
import subprocess
import sys
import os
import string
import re
import struct
import argparse
import time


def interactive_fuzz(vulnerable_program,max_depth=100,print_debug=False):
    if print_debug:
        print(f"Starting Interactive Fuzzer on {vulnerable_program}...")


    pattern_len = 5000
    cyclic_pattern = generate_cyclic_pattern(pattern_len)
    # Truncate to desired length
    cyclic_pattern = cyclic_pattern[:pattern_len] + b"\n"

    # We will try injecting the pattern at different "steps"
    # Iteration 0: Pattern
    # Iteration 1: 1\n + Pattern
    # Iteration 2: 1\n + 1\n + Pattern
    


    for depth in range(max_depth):
        if print_debug:
            print(f"Depth: {depth} ---")
        
        # Start the process for every attempt
        proc = subprocess.Popen(
            [f"./{vulnerable_program}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            # 1. Send inputs (1\n)
            for i in range(depth):
                if proc.poll() is not None: break # already died
                proc.stdin.write(b"1\n")
                proc.stdin.flush()
                # Tiny sleep to let the C program process the scanf
                time.sleep(0.05) 

            # Check if it's still alive 
            if proc.poll() is None:
                
                if print_debug:
                    print(f"    -> Sending {len(cyclic_pattern)} byte payload...")
                proc.stdin.write(cyclic_pattern)
                proc.stdin.flush()
                
                # Wait a moment for the crash
                time.sleep(0.2)
            
            # Check return code
            return_code = proc.poll()
            
            if return_code == -11:
                if print_debug:
                    print(f"\nSEGFAULT DETECTED at Depth {depth}!")
                    print(f"Payload structure: ('1\\n' * {depth}) + CYCLIC_PATTERN")
                

                prefix = (b"1\n" * depth) 

                
                proc.kill()
                return depth,prefix
            else:
                print(f"    -> Process finished with code {return_code} (No Segfault)")
                proc.kill()

        except BrokenPipeError:
            print("    -> Broken Pipe (Process died unexpectedly)")
    if print_debug:
        print("[-] No segfault found.")
    return None




def de_bruijn(n):
    try:
        # Defined alphabet: 0-9, A-Z, a-z (62 chars)
        _alphabet = string.digits + string.ascii_uppercase + string.ascii_lowercase
        k = len(_alphabet)
        a = [0] * k * n
        sequence = []

        def db(t, p):
            if t > n:
                if n % p == 0:
                    sequence.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    db(t + 1, t)
        
        db(1, 1)
        return "".join(_alphabet[i] for i in sequence)
    except Exception as e:
        print(f"Error generating sequence: {e}")
        return ""

def generate_cyclic_pattern(length):
    # Generate a full De Bruijn sequence
    # We use n=4 because we are targeting 32-bit architectures (4 byte registers)
    full_pattern = de_bruijn(4)
    if length > len(full_pattern):
        print("Warning: Requested length exceeds max unique pattern size.")
    return full_pattern[:length].encode()

def cyclic_find(packed_value, pattern):
    # packed_value is the 4 bytes found in EIP (e.g., b'Aa0A')
    return pattern.find(packed_value)

def parse_input_template(template_str):
    """
    Converts a string input like "1\n2\n" into bytes b'1\n2\n'.
    Handles escape sequences safely.
    """
    if not template_str:
        return b""
    try:
        # This converts literal "\x41" or "\n" strings to bytes
        return bytes(template_str, "utf-8").decode("unicode_escape").encode("latin-1")
    except Exception:
        # Fallback for simple strings
        return template_str.encode()

def find_if_fileinput(vulnerable_program, extra_flags=None):
    """
    Determines if the vulnerable input takes a file argument or stdin.
    """

    payload = b"A" * 1000000
    filename = "fuzz_input"
    
    with open(filename, "wb") as f:
        f.write(payload)

    is_file_mode = False



    try:
        result = subprocess.run(
            [f"./{vulnerable_program}", filename] + (extra_flags if extra_flags else []), 
            stdin=subprocess.DEVNULL, 
            capture_output=True, 
            timeout=2
        )
        
        # If it segfaults (-11) or exits successfully without hanging, 
        
        if result.returncode == -11: 
            is_file_mode = True
            
    except subprocess.TimeoutExpired:
        
        is_file_mode = False

    
    if os.path.exists(filename):
        os.remove(filename)

    return is_file_mode

def find_offset(vulnerable_program, fileinput=True, input_prefix=b"", extra_flags=[], print_debug=False):
    """
    Uses GDB to find the EIP offset.
    input_prefix: Bytes to send BEFORE the crash pattern (e.g. menu selections).
    """
    if print_debug:
        print("Starting Cyclic Fuzzing with De Bruijn Sequence...")

    # Pattern generation
    pattern_len = 5000
    cyclic_pat = generate_cyclic_pattern(pattern_len)
    
    # Combine template + pattern
    full_payload = input_prefix + cyclic_pat
    
    fuzz_filename = "fuzz_pattern"
    with open(fuzz_filename, "wb") as f:
        f.write(full_payload)

    # Construct GDB Command
    # Using --batch to run GDB non-interactively
    
    run_cmd = ""
    target_args = f"./{vulnerable_program}"
    
    # Construct the argument list for the target inside GDB
    # If flags exist, join them. 
    flags_str = " ".join(extra_flags) if extra_flags else ""

    if fileinput:
        # run <flags> <filename>
        run_args = f"{flags_str} {fuzz_filename}".strip()
        run_cmd = f"run {run_args}"
    else:
        # run <flags> < <filename>
        run_args = f"{flags_str} < {fuzz_filename}".strip()
        run_cmd = f"run {run_args}"

    gdb_cmd = [
        "gdb", "--batch",
        "-ex", run_cmd,
        "-ex", "info registers eip",
        target_args
    ]
    if print_debug:

        print(f"[*] Executing GDB: {' '.join(gdb_cmd)}")

    try:
        result = subprocess.run(gdb_cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout
        
        # Parse EIP
        match = re.search(r"eip\s+(0x[0-9a-fA-F]+)", output)
        
        if match:
            eip_hex = match.group(1)
            eip_int = int(eip_hex, 16)
            
            if print_debug:
                print(f"[+] Crash detected. EIP: {hex(eip_int)}")
            
            eip_bytes = struct.pack("<I", eip_int)
            
            # Find offset in the cyclic pattern
            # Note: The offset is relative to the START of the cyclic pattern, 
            # not the start of the whole input (prefix + pattern).
            offset = cyclic_find(eip_bytes, cyclic_pat)
            
            if offset != -1:
                total_offset = len(input_prefix) + offset
                if print_debug:
                    print(f"[+] Offset found in pattern: {offset}")
                    print(f"[+] Total payload size to reach EIP (Prefix + Offset): {total_offset}")
                
                # Cleanup
                if os.path.exists(fuzz_filename): os.remove(fuzz_filename)
                return offset
            else:
                if print_debug:
                    print("[-] EIP value not found in pattern.")
                return -1
        else:
            if print_debug:
                print("[-] Could not find EIP in GDB output.")
            return -1

    except subprocess.TimeoutExpired:
        if print_debug:
            print("[-] GDB Timed out.")
        
        return -1
    except Exception as e:
        print(f"[-] Error: {e}")
        return -1
    finally:
        if os.path.exists(fuzz_filename):
            try:
                pass
                # os.remove(fuzz_filename)
            except:
                pass

def fuzz(vulnerable_program, fileinput=None, input_template=None, flags=None, print_debug=False,brute_depth=None):
    """
    Main entry point for fuzzing logic. 
    Can be called from CLI or imported as a module.
    
    Args:
        vulnerable_program (str): Path to binary.
        fileinput (int/bool): 1 for file input, 0 for stdin, None for auto-detect.
        input_template (str/bytes): Prefix data before overflow.
        flags (list): Extra flags to pass to binary.
    """
    
    # 1. Validate Program Existence
    if not os.path.exists(vulnerable_program):
        print(f"[-] Error: Vulnerable program '{vulnerable_program}' does not exist.")
        sys.exit(1)

    total_prefix=b""

    # 2. Parse Flags
    # Ensure flags is a list
    if flags is None:
        extra_flags = []
    elif isinstance(flags, str):
        extra_flags = flags.split()
    else:
        extra_flags = flags

    # 3. Handle Input Template
    # Ensure prefix is bytes
    if input_template is None:
        prefix_bytes = b""
    elif isinstance(input_template, str):
        prefix_bytes = parse_input_template(input_template)
    else:
        prefix_bytes = input_template

    
    total_prefix= prefix_bytes

    # 4. Detect Mode (if not provided)
    if fileinput is None:
        if print_debug:
            print("[*] Input mode not specified. Auto-detecting...")
        is_file_mode = find_if_fileinput(vulnerable_program, extra_flags)
        if print_debug:
            print(f"[*] Detected mode: {'File Input' if is_file_mode else 'STDIN'}")
    else:
        # Convert integer 0/1 to bool if necessary
        is_file_mode = bool(int(fileinput))
        if print_debug:
            print(f"[*] Using specified mode: {'File Input' if is_file_mode else 'STDIN'}")
    
    if brute_depth is not None:
        max_depth = brute_depth
        if print_debug:
            print(f"[*] User specified max depth: {max_depth}")
    elif input_template is not None or is_file_mode:
        max_depth = 0
        if print_debug:
            print(f"[*] Template provided. Disabling depth brute-force (Depth: 0).")
    else:
        max_depth = 100
        if print_debug:
            print(f"[*] No template provided. Activating Blind Fuzzing (Max Depth: {max_depth}).")


    
    if max_depth:
        amount, depth_prefix = interactive_fuzz(vulnerable_program,max_depth,print_debug)
        if amount:
            total_prefix=depth_prefix

    

    offset = find_offset(
        vulnerable_program, 
        fileinput=is_file_mode, 
        input_prefix=total_prefix, 
        extra_flags=extra_flags,
        print_debug=print_debug
    )

    if offset != -1:    
        return total_prefix,offset
    if print_debug:
        print(f"\n[-] Fuzzing finished. No crash detected within depth {max_depth}.")
    return total_prefix,None






if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Buffer Overflow Helper: Fuzzing & Offset Detection",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("program", help="Path to the vulnerable executable")
    
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

    # Call fuzz
    _,offset = fuzz(
        vulnerable_program=args.program,
        fileinput=args.fileinput,
        input_template=args.inputs,
        flags=args.flags,
        brute_depth=args.brute_depth,
        print_debug=True
    )

    if offset != -1:
        print(f"[*] Detected offset: {offset}")
    else:
        print("[-] Failed to detect offset.")
        sys.exit(1)
    