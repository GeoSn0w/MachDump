# MachDump
A C Mach-O Header Dump tool was written for practicing purposes. Works With x86 and x86_64 binaries.
Didn't bother with Mach-O armv7 and AARCH64 nor with FAT files but will probably do in the future.
The program is written in 100% C so with `some` modifications you may be able to port it if needed. (You may wanna remove the macOS-specific `system(clear);` though).

### Mach-O Goodies
To put it simply, the Mach-O binaries (assume here x86 and 64-Bit) have a Mach-O Header that you can find very well detailed on Apple's official source code. The file is called `loader.h`. Here is the `loader.h` file of the `xnu-2050.18.24`: https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h

Inside this file you can clearly see, very well put together the Mach-O header which without any bells and whistles looks pretty much like this:

```c
struct mach_header {
  uint32_t      magic;
  cpu_type_t    cputype;
  cpu_subtype_t cpusubtype;
  uint32_t      filetype;
  uint32_t      ncmds;
  uint32_t      sizeofcmds;
  uint32_t      flags;
};
```
<p align="center">
  <img src="https://user-images.githubusercontent.com/15067741/41814439-efa01b16-7719-11e8-8900-3841fc7e72d5.png"/>
</p>

The `magic` is quite important. We can easily identify if a file is a Mach-O Object file just by parsing the magic. Of course, Mach-O files are of a big variety, but as long as the `magic` checks out, you can proceed with trying to parse the rest of the header. If it doesn't, you can call the quits. Either the file header was mangled or the file itself is not Mach-O.

The `magic` can take various forms. Only 32-Bit Mach-O you will find out that the magic has the value `0xfeedface` or `0xcefaedfe`if swapped. On 64-Bit Mach-O the `magic` is either `0xfeedfacf` or `0xcffaedfe` if swapped. If you open a Mach-O binary in a HEX editor, you are likely to find out the swapped version.

Apart from the `magic`, the header also contains the `cputype` and `cpusubtype` which are self-explanatory. The `ncmds` is the number of load commands. After the header, you will find the `Segment Command` which on the XNU source code in the `loader.h` is looking like this:

```c
struct segment_command {
  uint32_t  cmd;
  uint32_t  cmdsize;
  char      segname[16];
  uint32_t  vmaddr;
  uint32_t  vmsize;
  uint32_t  fileoff;
  uint32_t  filesize;
  vm_prot_t maxprot;
  vm_prot_t initprot;
  uint32_t  nsects;
  uint32_t  flags;
};
```
Each segment in the Mach-O file has the afore-mentioned components. Most notably, a name, a memory address, a memory size, protection-related info, a count for the sections and flags. 

The most common segments you will find in an executable Mach-O binary are:

```
__PAGEZERO ; This is the pagezero segment which has no protections and catches NULLs.
__TEXT     ; Pretty much contains the entire code (in the __text section)
__DATA     ; This contains the __data section which contains all the initialized data. If you initialize a variable, here it goes.
__bss      ; This segment contains uninitialized data.
__LINKEDIT ; This segment containing all structs created and maintained by the link editor.
```

There are, indeed, more segments you may find, such as `__OBJC` which is the Objective-C runtime segment or `__symbol_table` which is the Symbol Table and so on, but those afore-mentioned are the principal segments.

In order to be able to get access to the Mach-O manipulation stuff, you need to import the following headers on macOS:

```
#include <mach-o/loader.h>
#include <mach-o/swap.h>
```
The entry offset of the file represents the offset of the main() function in a C program that is compiled as a Mach-O binary.

The following part of the `loader.h` header describes this structure in-depth:

```c
/*
 * The entry_point_command is a replacement for thread_command.
 * It is used for main executables to specify the location (file offset)
 * of main().  If -stack_size was used at link time, the stacksize
 * field will contain the stack size need for the main thread.
 */
struct entry_point_command {
    uint32_t  cmd;    /* LC_MAIN only used in MH_EXECUTE filetypes */
    uint32_t  cmdsize;    /* 24 */
    uint64_t  entryoff;    /* file (__TEXT) offset of main() */
    uint64_t  stacksize;/* if not zero, initial stack size */
};
```
The header is self explanatory. If you parse the `entryoff` member of the `entry_point_command` structure, you can easily get the offset of the main() function. In my program I do this something like this:

```c
if (command->cmd == LC_MAIN){
      struct entry_point_command *entry = macho_loader(object_file, the_offset, sizeof(struct entry_point_command));
      printf("[*] Found Main Entry Offset: 0x%llx\n",entry->entryoff); // We just print the entryoff member of the entry_point_command
      free(entry); //Free the struct from the memory.
}
```

As you can see, the code is pretty simple. We iterate through the `ncommands` and once we find `LC_MAIN` we build a new entry_point_command pointer structure and we feed in the `object_file` which is the binary loaded, the offset and the size.
After this, it is just a matter of printing the `entryoff` member of the `entry_point_command` which is of type `uint64_t` so we can use the `0x%llx` format specifier for `printf()`. Of course, `0x` is for cosmetic purposes to make it clear it is `hexadecimal` and the `llx` stands for `unsigned long long int` represented as `hexadecimal` by the `x` at the end. 

### Compiling
To compile, run `gcc mach_dump.c -o mach_dump`
Add paths as needed.

### Example Output
```bash
MachDump v1.0 by GeoSn0w (@FCE365)

Located Magic: 0xfeedface
Swapped Magic: 0xcefaedfe
[*] Found Mach-O 32-Bit Object File
[*] Found CPU TYPE: 7
[*] Found CPU SUBTYPE: 3
[*] Found FLAGS: 0x01200085
[*] Found Size: 1044 bytes
===============================================
[*] Found Segment: __PAGEZERO
[*] Found Segment Memory Address (vmaddr): 0x0000000000000000
[*] Found Segment Memory Size (vmsize): 0x0000000000001000
[*] Found 0 structures in the segment
===============================================
[*] Found Segment: __TEXT
[*] Found Segment Memory Address (vmaddr): 0x0000000000001000
[*] Found Segment Memory Size (vmsize): 0x0000000000002000
[*] Found 5 structures in the segment
===============================================
[*] Found Segment: __DATA
[*] Found Segment Memory Address (vmaddr): 0x0000000000003000
[*] Found Segment Memory Size (vmsize): 0x0000000000001000
[*] Found 2 structures in the segment
===============================================
[*] Found Segment: __LINKEDIT
[*] Found Segment Memory Address (vmaddr): 0x0000000000004000
[*] Found Segment Memory Size (vmsize): 0x0000000000001000
[*] Found 0 structures in the segment
===============================================
[*] Found Symbol Table at 0x31fc and it has 26 entries
[*] Found Main Entry Offset: 0x1140
iMac:~ geosn0w$ 
```
### Contact Me
Twitter: @FCE365 (https://twitter.com/FCE365)

YouTube Channel (iOS/macOS related): http://youtube.com/fce365official
