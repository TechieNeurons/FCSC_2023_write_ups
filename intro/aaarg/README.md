1. Open in Ghidra
2. Find the function calling libc_start_main and go in the function called
3. We have a function called putc and a pointer to some data, go and copy the data then print :

```
toto = [ 0x53, 0xe2, 0x80, 0x8d, 0x43, 0xe2, 0x80, 0x8d, 0x7b, 0xe2, 0x80, 0x8d, 0x66, 0xe2, 0x80, 0x8d, 0x39, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x33, 0xe2, 0x80, 0x8d, 0x38, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x64, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x63, 0xe2, 0x80, 0x8d, 0x65, 0xe2, 0x80, 0x8d, 0x39, 0xe2, 0x80, 0x8d, 0x64, 0xe2, 0x80, 0x8d, 0x64, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x33, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x39, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x65, 0xe2, 0x80, 0x8d, 0x35, 0xe2, 0x80, 0x8d, 0x33, 0xe2, 0x80, 0x8d, 0x65, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x65, 0xe2, 0x80, 0x8d, 0x63, 0xe2, 0x80, 0x8d, 0x31, 0xe2, 0x80, 0x8d, 0x38, 0xe2, 0x80, 0x8d, 0x30, 0xe2, 0x80, 0x8d, 0x63, 0xe2, 0x80, 0x8d, 0x35, 0xe2, 0x80, 0x8d, 0x61, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x33, 0xe2, 0x80, 0x8d, 0x64, 0xe2, 0x80, 0x8d, 0x62, 0xe2, 0x80, 0x8d, 0x62, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x63, 0xe2, 0x80, 0x8d, 0x33, 0xe2, 0x80, 0x8d, 0x36, 0xe2, 0x80, 0x8d, 0x34, 0xe2, 0x80, 0x8d, 0x66, 0xe2, 0x80, 0x8d, 0x65, 0xe2, 0x80, 0x8d, 0x31, 0xe2, 0x80, 0x8d, 0x33, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x66, 0xe2, 0x80, 0x8d, 0x63, 0xe2, 0x80, 0x8d, 0x36, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x32, 0xe2, 0x80, 0x8d, 0x31, 0xe2, 0x80, 0x8d, 0x64, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x39, 0xe2, 0x80, 0x8d, 0x39, 0xe2, 0x80, 0x8d, 0x37, 0xe2, 0x80, 0x8d, 0x63, 0xe2, 0x80, 0x8d, 0x35, 0xe2, 0x80, 0x8d, 0x34, 0xe2, 0x80, 0x8d, 0x65, 0xe2, 0x80, 0x8d, 0x38, 0xe2, 0x80, 0x8d, 0x64, 0xe2, 0x80, 0x8d, 0x7d ]

flag = ''
for i in range(0, len(toto), 4):
	flag += chr(toto[i])
 
print (flag)
```
