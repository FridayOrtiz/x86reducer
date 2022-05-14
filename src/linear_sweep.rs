use crate::disasm::DisasmError;
use crate::instruction::{Instruction, Mnemonic, MnemonicByte, MnemonicName, Operand};
use std::panic;

fn parse_instruction(bytes: &[u8], idx: usize) -> Instruction {
    let default = |byte| Instruction {
        prefix: None,
        mnemonic: Some(Mnemonic {
            mnemonic_byte: MnemonicByte::One(byte),
            mnemonic_name: MnemonicName::DB,
        }),
        modrm: None,
        sib: None,
        displacement: None,
        immediate: None,
        operands: vec![Operand::Byte(byte)],
        label: None,
        size: 1,
    };
    let instruction = panic::catch_unwind(|| Instruction::decode(bytes, idx));
    instruction.unwrap_or_else(|_| default(bytes[idx]))
}

pub(crate) fn linear_sweep(bytes: Vec<u8>) -> Result<Vec<Instruction>, DisasmError> {
    let len = bytes.len();
    let mut idx = 0;
    let mut insns = vec![];

    while idx < len {
        let insn = parse_instruction(&bytes, idx);
        idx += insn.size;
        insns.push(insn);
    }

    Ok(insns)
}
