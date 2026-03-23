# Ghost License

## Challenge metadata
- Title: Ghost License
- Category: Reverse Engineering / Crypto
- Suggested level: 3
- Final flag: Stud-CTF{gh0st_l1cense_mult1ch3ck_byp4ss}

## Player-facing description
You received a local license validator binary from a software vendor. The vendor claims the validation cannot be bypassed. Analyze the program and recover a valid license key that reveals the flag.

## Intended solve path
1. Inspect strings and entry flow in Ghidra, Cutter, or IDA.
2. Identify that one check only prints a status line and does not control success.
3. Locate the real validation path:
   - key shape and character constraints
   - byte transform check (xor + rotate)
   - checksum comparison
4. Reconstruct the expected payload bytes and invert the transform.
5. Build a key that passes all real checks.
6. Run the binary with that key to print the decoded flag.

## Common wrong paths
- Treating the legacy entropy check as mandatory.
- Brute forcing without reconstructing the transform.
- Ignoring checksum validation after solving the transform stage.

## Organizer notes
- Working sample key in this generator version: GLIC-7H2K-9M4P-3T8R
- The binary stores an encoded flag and decodes it only on success.
- Regenerate constants if you change the key or flag.
