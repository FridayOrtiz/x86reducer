# x86reducer

A Rust program for disassembling raw x86 assembly, written for JHU's Reverse Engineering
and Vulnerability Analysis course. The complete x86 instruction set is NOT implemented,
but the code is modularized such that new instructions can be easily added.

## Disassembly Mode

The primary mode, returns the disassembled output of a target binary. Note that the
binary must only contain x86 assembly instructions, with the code beginning at offset 0.

```
❯ printf >tmp.asm "[BITS 32]\n\nstart:\n\txchg eax, eax\n"
❯ nasm tmp.asm
❯ cargo run -- -i tmp
    Finished dev [unoptimized + debuginfo] target(s) in 0.01s
     Running `target/debug/reducer -i tmp`
0x00000000:     90                      nop 

```

## Byte Decoding Mode

You can also manually specify a MODR/M byte or MODR/M byte plus SIB byte,
and `reducer` will decode it for you.

```
❯ cargo run -- --modrm 4d --sib 00
Finished dev [unoptimized + debuginfo] target(s) in 0.01s
Running `target/debug/reducer --modrm 4d --sib 00`
Decoding: 4D
ModRM { md: RmByte, reg: ECX, rm: EBP }
Decoding: 00
SIB { scale: None, index: EAX, base: EAX }
```

# Known Issues in Disassembly Mode

There are several known issues which are entirely cosmetic.

* Signed bytes will sometimes be output as sign extended DWORDs.
* Unsigned bytes will sometimes be output as DWORDs.
* Instructions will be generated with ghost entries. For example, `reducer`
will output `call [    + esp + 0x00000033 ]` instead of `call [esp + 0x33]`.
* SIB bytes scaled by `esp` will not render correctly. E.g., they include a
"blank" `esp` followed by the scale, such as `[*2 0x11223344]`.

There is one known issue which is not entirely cosmetic.

* Bad inputs are handled by throwing and catching panics. This is hacky and 
terrible.
