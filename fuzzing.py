
import subprocess
import sys
import os
import string
import re
import struct
import argparse

# def find_offset(vulnerable_program, fileinput=True):
#     # either file inputs or stdio
#     # looking for a seg fault
#     # for now if not fileinput or stdio just exit

#     # start with trying a file input
#     if fileinput:
#         return file_input_mode(vulnerable_program)
#     else:
#         return stdio_mode(vulnerable_program)


def file_input_mode(vulnerable_program):
    
    l=0
    r=1000000000
    while l < r:
        mid = (l + r) // 2
        input_data = b"A" * mid
        with open("fuzz_input", "wb") as f:
            f.write(input_data)

        
        try:
            # ignore stdout
            result = subprocess.run([f"./{vulnerable_program}", "fuzz_input"], stdout=subprocess.DEVNULL, timeout=5)
            
            if result.returncode == -11:  # Segmentation fault
                r = mid
            else:
                l = mid + 1
        except subprocess.TimeoutExpired:
            l = mid + 1
    

    if print_debug:
        print(f"Minimum input size causing segfault: {l} bytes")
    # remove fuzz_input
    os.remove("fuzz_input")

    return l+4

def stdio_mode(vulnerable_program):

    l=0
    r=1000000000
    while l < r:
        mid = (l + r) // 2
        input_data = b"A" * mid

        

        try:
            # ignore stdout
            result = subprocess.run([f"./{vulnerable_program}"], input=input_data, stdout=subprocess.DEVNULL, timeout=5)
            
            if result.returncode == -11:  # Segmentation fault
                r = mid
            else:
                l = mid + 1
        except subprocess.TimeoutExpired:
            l = mid + 1
    if print_debug:
        print(f"Minimum input size causing segfault: {l} bytes")
    return l+4

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
        # This converts literal "\x41" or "\n" strings to actual bytes
        # encode('latin-1') and decode('unicode_escape') is a common python trick
        # or we can use literal_eval for complex types, but bytes(x, 'utf-8') is safer for raw CLI
        return bytes(template_str, "utf-8").decode("unicode_escape").encode("latin-1")
    except Exception:
        # Fallback for simple strings
        return template_str.encode()

def find_if_fileinput(vulnerable_program, extra_flags=None):
    # Create a large payload to trigger potential crashes
    payload = b"A" * 1000000000 
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
        print("[*] Starting Cyclic Fuzzing with De Bruijn Sequence...")

    # Pattern generation
    pattern_len = 5000
    cyclic_pat = generate_cyclic_pattern(pattern_len)
    
    # Combine template + pattern
    full_payload = input_prefix + cyclic_pat
    
    fuzz_filename = "fuzz_pattern"
    with open(fuzz_filename, "wb") as f:
        f.write(full_payload)

    # Construct GDB Command
    # We use --batch to run GDB non-interactively
    
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
                os.remove(fuzz_filename)
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

    base_prefix= prefix_bytes

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
    elif input_template is not None:
        max_depth = 0
        if print_debug:
            print(f"[*] Template provided. Disabling depth brute-force (Depth: 0).")
    else:
        max_depth = 100
        if print_debug:
            print(f"[*] No template provided. Activating Blind Fuzzing (Max Depth: {max_depth}).")

    # 4. The Loop
    pad_char = b"1\n" 

    for i in range(max_depth + 1):
        current_padding = pad_char * i
        total_prefix = base_prefix + current_padding
        
        # Fancy carriage return printing so we don't spam the console
        sys.stdout.write(f"    -> Scanning depth {i} (Prefix: {len(total_prefix)} bytes)... \r")
        sys.stdout.flush()
        
        offset = find_offset(
            vulnerable_program, 
            fileinput=is_file_mode, 
            input_prefix=total_prefix, 
            extra_flags=extra_flags,
            print_debug=False # Only prints on success
        )

        if offset != -1:
            if print_debug:
                offset = find_offset(
                vulnerable_program, 
                fileinput=is_file_mode, 
                input_prefix=total_prefix, 
                extra_flags=extra_flags,
                print_debug=True # Only prints on success
                )
                
            return i,offset
    if print_debug:
        print(f"\n[-] Fuzzing finished. No crash detected within depth {max_depth}.")
    return None
    # 5. Run Fuzzing
    offset = find_offset(
        vulnerable_program, 
        fileinput=is_file_mode, 
        input_prefix=prefix_bytes, 
        extra_flags=extra_flags,
        print_debug=print_debug
    )

    return offset





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
    