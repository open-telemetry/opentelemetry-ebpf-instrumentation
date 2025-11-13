# Working with C Code for eBPF in VS Code

This repository already includes the configuration needed for working on the eBPF C sources:

- `.clangd`

You do not need to configure this file. You only need to set up VS Code to use it correctly.

## What You Need To Do

### 1. Install clangd and disable IntelliSense

Install the clangd extension.  
Disable the Microsoft C/C++ extension (or at least disable its IntelliSense engine).  
If IntelliSense is active, clangd never runs.

IntelliSense uses the EDG front end, which does not match how clang handles GNU17 or the kernel-style extensions used in eBPF code. It often produces incorrect parsing and diagnostics. clangd uses the same frontend as the actual compiler, so its behavior matches how the code is really built.

### 2. Why clangd is the correct backend

The eBPF C code in this repository is written for clang in GNU17 mode.  
clangd uses the same parser and semantics, and the `.clangd` file in the repo already defines the expected rules and mode.  
This gives consistent, accurate diagnostics and correct behavior for the kernel and BPF headers.

### 3. What you get when clangd is active

- Correct GNU17 parsing  
- Proper handling of GNU extensions used by kernel and eBPF code  
- No IntelliSense inconsistencies  
- Diagnostics that reflect real compiler behavior

### 4. Verify that clangd is active

Look at the bottom-right of VS Code. It should show "clangd".  
If it shows "C/C++", IntelliSense is still running and needs to be disabled.

### Optional: Make VS Code Treat .h Files as C

VS Code treats `.h` files as C++ by default. If you want the bottom-right language mode to show "C" and keep the editor consistent with the C-only eBPF code in this repo, add this to your VS Code settings:

```json
"files.associations": {
    "*.h": "c"
}
