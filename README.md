<p align="center" >
     <br><br>
<img width="45%" src="/ressources/maat_logo.png"/> <br>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License: MIT"> &nbsp; &nbsp;
  <img src="https://img.shields.io/badge/Build-Linux-green" alt="Build: Linux">  &nbsp; &nbsp;
  <img src="https://img.shields.io/badge/Version-v0.1-green" alt="Version: 0.1"> &nbsp; &nbsp;
  <a href="http://maat.re"><img src="https://img.shields.io/badge/Website-maat.re-blue" alt="Website: maat.re"></a>
  <br>
  <br>
  <br>
</p>


# About

Maat is an open-source Dynamic Symbolic Execution framework used for Binary Analysis. It provides several functionnalities such as symbolic execution, taint analysis, constraint solving, binary loading, and X86 assembly lifting: https://maat.re

Key features:

- **Portable**: Maat has very few dependencies to other projects
- **Fast**: Maat was designed to scale to real-world usage
- **Python Bindings**: Use Maat effortlessly in python scripts
     
# Getting started
- [Installation](https://maat.re/install.html)
- [Tutorials](https://maat.re/tutorials.html)
     - [First steps](https://maat.re/tutorial_first_steps.html)
- [Documentation](https://maat.re)
     - [Python API](https://maat.re/python_api.html)
- [Examples](#Examples)
- [Contact](#contact)
- [Licence](#licence)

# Examples
Symbolically execute a binary:

```Python

# Create a symbolic engine for Linux X86
sym = SymbolicEngine(ARCH.X86, SYS.LINUX)

# Set program arguments and load the binary
args = [ Arg(b'first_arg'), Arg(b'second_arg', tainted=True)]
Loader(sym).load("my_binary", BIN.ELF32, args)

# Start executing the loaded binary
sym.execute()
```

Breakpoints:

```Python
def print_eax(sym):
     print("Eax is: " + str(sym.regs.get(X86.EAX)))

def print_constraint(sym):
     print("Adding path constraint: " + str(sym.info.path_constraint))

sym.breakpoint.add(BREAK.REGISTER_R, "reading_eax", X86.EAX, callback=print_eax)
sym.breakpoint.add(BREAK.PATH_CONSTRAINT, "path", callback=print_constraint)
sym.execute()
```

Snapshots:

```Python
snap1 = sym.take_snapshot()
eax1 = sym.regs.as_unsigned(X86.EAX)
sym.execute(100) # Execute 100 instructions

snap2 = sym.take_snapshot()
eax2 = sym.regs.as_unsigned(X86.EAX)
sym.execute(100)

sym.restore_snapshot(snap2) # Go back to snapshot 2
assert(sym.regs.as_unsigned(X86.EAX) == eax2)
sym.restore_snapshot(snap1, remove=True) # Go back to snapshot 1 and delete it
assert(sym.regs.as_unsigned(X86.EAX) == eax1)
 
```

# Contact
**Info** - info@maat.re
**Boyan MILANOV** - boyan (dot) milanov (at) hotmail (dot) fr

# Licence
Maat is distributed under the **MIT licence**.
