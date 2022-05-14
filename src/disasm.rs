use crate::instruction::Instruction;
use std::collections::HashMap;

#[derive(Debug)]
pub(crate) enum DisasmError {
    FileIOError(String),

    #[allow(dead_code)]
    /// Returned when the instructions have not yet been parsed.
    InstructionsNotParsed,
}

#[derive(Clone)]
pub(crate) struct Program {
    bytes: Vec<u8>,
    instructions: Option<Vec<Instruction>>,
    labels: HashMap<isize, String>,
}

impl Program {
    pub(crate) fn new(file_name: &str) -> Result<Program, DisasmError> {
        let bytes =
            std::fs::read(file_name).map_err(|e| DisasmError::FileIOError(format!("{}", e)))?;

        Ok(Program {
            bytes,
            instructions: None,
            labels: HashMap::new(),
        })
    }

    pub(crate) fn parse(
        &mut self,
        parser: fn(bytes: Vec<u8>) -> Result<Vec<Instruction>, DisasmError>,
    ) -> Result<(), DisasmError> {
        // parse instructions
        self.instructions = Some(parser(self.bytes.clone())?);
        // extract labels
        if let Some(insns) = &self.instructions {
            for insn in insns {
                if let Some(label) = &insn.label {
                    self.labels.insert(
                        label.displacement + label.index as isize,
                        label.name.to_owned(),
                    );
                }
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn get_instructions(&self) -> Result<Vec<Instruction>, DisasmError> {
        self.instructions
            .clone()
            .ok_or(DisasmError::InstructionsNotParsed)
    }

    #[allow(dead_code)]
    fn get_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub(crate) fn print_disassembly(&self) {
        if let Some(insns) = &self.instructions {
            let mut idx = 0;
            for insn in insns {
                let bytes = insn.get_bytes_string();
                for i in idx..idx + insn.size {
                    if let Some(label) = self.labels.get(&(i as isize)) {
                        println!("{}:", label);
                    }
                }
                if insn.label.is_some() {
                    //println!("{:?}", insn.label);
                    println!(
                        "{:#010X}:\t{: <22}\t{:#}",
                        idx,
                        bytes,
                        insn.to_labeled_string()
                    );
                } else {
                    println!("{:#010X}:\t{: <22}\t{:#}", idx, bytes, insn);
                }
                idx += insn.size;
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn dump_bytes(&self) {
        let mut ctr = 1;

        for byte in &self.bytes {
            print!("{:02X} ", byte);
            if ctr % 8 == 0 {
                print!("    ");
            }

            if ctr % 16 == 0 {
                println!();
            }

            ctr += 1;
        }

        println!();
    }
}

#[cfg(test)]
mod instruction_tests {
    use crate::instruction::modrm::{MODBits, ModRM, RegBits, RmBits};
    use crate::instruction::sib::{Base, Index, Scale, SIB};
    use crate::instruction::{
        DisplacementByte, ImmediateByte, Instruction, Label, Mnemonic, MnemonicByte, MnemonicName,
        Operand, Prefix,
    };

    #[test]
    fn test_repne_cmpsd() {
        let cmpsd: [u8; 2] = [0xF2, 0xA7];
        let cmpsd = Instruction::decode(&cmpsd, 0);
        assert_eq!(
            cmpsd,
            Instruction {
                prefix: Some(Prefix::REPNE),
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xA7),
                    mnemonic_name: MnemonicName::CMPSD
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 2
            }
        );
    }

    #[test]
    fn test_push() {
        let push: [u8; 1] = [0x52];
        let push = Instruction::decode(&push, 0);
        assert_eq!(
            push,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x52),
                    mnemonic_name: MnemonicName::PUSH
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX],
                label: None,
                size: 1
            }
        );

        let push: [u8; 5] = [0x68, 0x44, 0x33, 0x22, 0x11];
        let push = Instruction::decode(&push, 0);
        assert_eq!(
            push,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x68),
                    mnemonic_name: MnemonicName::PUSH
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::Imm32(0x11223344)],
                label: None,
                size: 5
            }
        );
    }

    #[test]
    fn test_mov_rm_imm() {
        // finally, an 11 byte instruction!
        let mov: [u8; 11] = [
            0xC7, 0x84, 0x70, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        ];
        let mov = Instruction::decode(&mov, 0);
        assert_eq!(
            mov,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xC7),
                    mnemonic_name: MnemonicName::MOV
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EAX,
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::Two,
                    index: Index::ESI,
                    base: Base::EAX
                }),
                displacement: Some(DisplacementByte::Four(0x55667788)),
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::Mem, Operand::Imm32(0x11223344)],
                label: None,
                size: 11
            }
        );
    }

    #[test]
    fn test_openc_mov() {
        let mov: [u8; 10] = [0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x44, 0x33, 0x22, 0x11];
        let mov = Instruction::decode(&mov, 5);
        assert_eq!(
            mov,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xB8),
                    mnemonic_name: MnemonicName::MOV
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::EAX, Operand::Imm32(0x11223344)],
                label: None,
                size: 5
            }
        );

        let mov: [u8; 10] = [0x00, 0x00, 0x00, 0xBF, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00];
        let mov = Instruction::decode(&mov, 3);
        assert_eq!(
            mov,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xBF),
                    mnemonic_name: MnemonicName::MOV
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::EDI, Operand::Imm32(0x11223344)],
                label: None,
                size: 5
            }
        );
    }

    #[test]
    fn test_movsd() {
        let movsd: [u8; 1] = [0xA5];
        let movsd = Instruction::decode(&movsd, 0);

        assert_eq!(
            movsd,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xA5),
                    mnemonic_name: MnemonicName::MOVSD
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1
            }
        );
    }

    #[test]
    fn test_lea() {
        let lea: [u8; 6] = [0x8D, 0x86, 0x44, 0x33, 0x22, 0x11];
        let lea = Instruction::decode(&lea, 0);
        assert_eq!(
            lea,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8D),
                    mnemonic_name: MnemonicName::LEA
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EAX,
                    rm: RmBits::ESI
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::EAX, Operand::Mem],
                label: None,
                size: 6
            }
        );

        let lea: [u8; 7] = [0x8D, 0x84, 0x8E, 0x44, 0x33, 0x22, 0x11];
        let lea = Instruction::decode(&lea, 0);
        assert_eq!(
            lea,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8D),
                    mnemonic_name: MnemonicName::LEA
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EAX,
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::Four,
                    index: Index::ECX,
                    base: Base::ESI
                }),
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::EAX, Operand::Mem],
                label: None,
                size: 7
            }
        );
    }

    #[test]
    fn test_jz_jnz_rel8() {
        let jz: [u8; 2] = [0x74, 0xFF];
        let jz = Instruction::decode(&jz, 0);
        assert_eq!(
            jz,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x74),
                    mnemonic_name: MnemonicName::JZ
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::One(0xFF)),
                operands: vec![Operand::Imm8(0xFF)],
                label: Some(Label {
                    name: "offset_0x00000001h".to_string(),
                    displacement: -1,
                    index: 2
                }),
                size: 2
            }
        );

        let jnz: [u8; 2] = [0x75, 0xFF];
        let jnz = Instruction::decode(&jnz, 0);
        assert_eq!(
            jnz,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x75),
                    mnemonic_name: MnemonicName::JNZ
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::One(0xFF)),
                operands: vec![Operand::Imm8(0xFF)],
                label: Some(Label {
                    name: "offset_0x00000001h".to_string(),
                    displacement: -1,
                    index: 2
                }),
                size: 2
            }
        );
    }

    #[test]
    fn test_jump() {
        let jmp32: [u8; 5] = [0xE9, 0xFB, 0x00, 0x00, 0x00];
        let jmp32 = Instruction::decode(&jmp32, 0);
        assert_eq!(
            jmp32,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xE9),
                    mnemonic_name: MnemonicName::JMP
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x000000FB)),
                operands: vec![Operand::Imm32(0x000000FB)],
                label: Some(Label {
                    name: "offset_0x00000100h".to_string(),
                    displacement: 251,
                    index: 5
                }),
                size: 5
            }
        );

        let jmp8: [u8; 5] = [0xEB, 0xFB, 0x00, 0x00, 0x00];
        let jmp8 = Instruction::decode(&jmp8, 0);
        assert_eq!(
            jmp8,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xEB),
                    mnemonic_name: MnemonicName::JMP
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::One(0xFB)),
                operands: vec![Operand::Imm8(0xFB)],
                label: Some(Label {
                    name: "offset_0xFFFFFFFDh".to_string(),
                    displacement: -5,
                    index: 2
                }),
                size: 2
            }
        );
    }

    #[test]
    fn test_inc() {
        let inc: [u8; 1] = [0x42];
        let inc = Instruction::decode(&inc, 0);
        assert_eq!(
            inc,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x42),
                    mnemonic_name: MnemonicName::INC
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX],
                label: None,
                size: 1
            }
        );
    }

    #[test]
    fn decode_f7_family() {
        let idiv: [u8; 2] = [0xF7, 0xF8];
        let idiv = Instruction::decode(&idiv, 0);
        assert_eq!(
            idiv,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xF7),
                    mnemonic_name: MnemonicName::IDIV
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EDI,
                    rm: RmBits::EAX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX],
                label: None,
                size: 2
            }
        );

        let idiv: [u8; 7] = [0xF7, 0xBC, 0x4F, 0x44, 0x33, 0x22, 0x11];
        let idiv = Instruction::decode(&idiv, 0);
        assert_eq!(
            idiv,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xF7),
                    mnemonic_name: MnemonicName::IDIV
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EDI,
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::Two,
                    index: Index::ECX,
                    base: Base::EDI
                }),
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 7
            }
        );

        let not: [u8; 6] = [0xF7, 0x15, 0x44, 0x33, 0x22, 0x11];
        let not = Instruction::decode(&not, 0);
        assert_eq!(
            not,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xF7),
                    mnemonic_name: MnemonicName::NOT
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EDX,
                    rm: RmBits::Disp32
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 6
            }
        );

        let test: [u8; 10] = [0xF7, 0x05, 0x44, 0x33, 0x22, 0x11, 0xDD, 0xCC, 0xBB, 0xAA];
        let test = Instruction::decode(&test, 0);
        assert_eq!(
            test,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xF7),
                    mnemonic_name: MnemonicName::TEST
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EAX,
                    rm: RmBits::Disp32
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: Some(ImmediateByte::Four(0xAABBCCDD)),
                operands: vec![Operand::Mem, Operand::Imm32(0xAABBCCDD)],
                label: None,
                size: 10
            }
        );
    }

    #[test]
    fn decode_dec_r32() {
        let dec: [u8; 1] = [0x48]; // dec eax
        let dec = Instruction::decode(&dec, 0);
        assert_eq!(
            dec,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x48),
                    mnemonic_name: MnemonicName::DEC
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX],
                label: None,
                size: 1
            }
        );

        let dec: [u8; 1] = [0x4E]; // dec eax
        let dec = Instruction::decode(&dec, 0);
        assert_eq!(
            dec,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x4E),
                    mnemonic_name: MnemonicName::DEC
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::ESI],
                label: None,
                size: 1
            }
        );
    }

    #[test]
    fn decode_call_rel32() {
        let call: [u8; 5] = [0xE8, 0xFC, 0xFF, 0xFF, 0xFF];
        let call = Instruction::decode(&call, 0);
        assert_eq!(
            call,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xE8),
                    mnemonic_name: MnemonicName::CALL
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0xFFFFFFFC)),
                operands: vec![Operand::Imm32(0xFFFFFFFC)],
                label: Some(Label {
                    name: "offset_0x00000001h".to_string(),
                    displacement: -4,
                    index: 5
                }),
                size: 5
            }
        )
    }

    #[test]
    fn decode_jcc_rel32() {
        let jz: [u8; 6] = [0x0F, 0x84, 0xFC, 0xFF, 0xFF, 0xFF];
        let jz = Instruction::decode(&jz, 0);
        assert_eq!(
            jz,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::Two(0x0F84),
                    mnemonic_name: MnemonicName::JZ
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0xFFFFFFFC)),
                operands: vec![Operand::Imm32(0xFFFFFFFC)],
                label: Some(Label {
                    name: "offset_0x00000002h".to_string(),
                    displacement: -4,
                    index: 6
                }),
                size: 6
            }
        );

        let jnz: [u8; 6] = [0x0F, 0x85, 0xFC, 0xFF, 0xFF, 0xFF];
        let jnz = Instruction::decode(&jnz, 0);
        assert_eq!(
            jnz,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::Two(0x0F85),
                    mnemonic_name: MnemonicName::JNZ
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0xFFFFFFFC)),
                operands: vec![Operand::Imm32(0xFFFFFFFC)],
                label: Some(Label {
                    name: "offset_0x00000002h".to_string(),
                    displacement: -4,
                    index: 6
                }),
                size: 6
            }
        );
    }

    #[test]
    fn decode_clflush() {
        let clflush: [u8; 7] = [0x0f, 0xae, 0x3d, 0x44, 0x33, 0x22, 0x11];
        let clflush = Instruction::decode(&clflush, 0);
        assert_eq!(
            clflush,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::Two(0x0FAE),
                    mnemonic_name: MnemonicName::CLFLUSH
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EDI,
                    rm: RmBits::Disp32
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 7
            }
        );

        let clflush: [u8; 8] = [0x0f, 0xae, 0xbc, 0x24, 0x44, 0x33, 0x22, 0x11];
        let clflush = Instruction::decode(&clflush, 0);
        assert_eq!(
            clflush,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::Two(0x0FAE),
                    mnemonic_name: MnemonicName::CLFLUSH
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EDI,
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::None,
                    base: Base::ESP
                }),
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 8
            }
        )
    }

    #[test]
    fn decode_returns() {
        let retf_imm: [u8; 3] = [0xCA, 0x3E, 0x00];
        let retf_imm = Instruction::decode(&retf_imm, 0);
        assert_eq!(
            retf_imm,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xCA),
                    mnemonic_name: MnemonicName::RETF
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Two(62)),
                operands: vec![Operand::Imm16(62)],
                label: None,
                size: 3
            }
        );

        let retf: [u8; 1] = [0xCB];
        let retf = Instruction::decode(&retf, 0);
        assert_eq!(
            retf,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xCB),
                    mnemonic_name: MnemonicName::RETF
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1
            }
        );

        let retn_imm: [u8; 3] = [0xC2, 0x3E, 0x00];
        let retn_imm = Instruction::decode(&retn_imm, 0);
        assert_eq!(
            retn_imm,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xC2),
                    mnemonic_name: MnemonicName::RETN
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Two(62)),
                operands: vec![Operand::Imm16(62)],
                label: None,
                size: 3
            }
        );

        let retn: [u8; 1] = [0xC3];
        let retn = Instruction::decode(&retn, 0);
        assert_eq!(
            retn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xC3),
                    mnemonic_name: MnemonicName::RETN
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1
            }
        )
    }
    #[test]
    fn decode_0xff() {
        // inc ebp
        let inc: [u8; 2] = [0xFF, 0xC5];
        let inc = Instruction::decode(&inc, 0);
        assert_eq!(
            inc,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xFF),
                    mnemonic_name: MnemonicName::INC
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EBP
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EBP],
                label: None,
                size: 2
            }
        );
        // dec [ ebp ]
        let dec: [u8; 3] = [0xFF, 0x4D, 0x00];
        let dec = Instruction::decode(&dec, 0);
        assert_eq!(
            dec,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xFF),
                    mnemonic_name: MnemonicName::DEC
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmByte,
                    reg: RegBits::ECX, // /1
                    rm: RmBits::EBP
                }),
                sib: None,
                displacement: Some(DisplacementByte::One(0)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 3
            }
        );

        // jmp [ edx + edx*1 + 0x55667788 ] ; this is how you get edx * 2
        let jmp: [u8; 7] = [0xff, 0xa4, 0x12, 0x88, 0x77, 0x66, 0x55];
        let jmp = Instruction::decode(&jmp, 0);
        assert_eq!(
            jmp,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xFF),
                    mnemonic_name: MnemonicName::JMP
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::ESP, // /4
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::EDX,
                    base: Base::EDX
                }),
                displacement: Some(DisplacementByte::Four(0x55667788)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 7
            }
        );

        // call [ esp ]
        let call: [u8; 3] = [0xFF, 0x14, 0x24];
        let call = Instruction::decode(&call, 0);
        assert_eq!(
            call,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xFF),
                    mnemonic_name: MnemonicName::CALL
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EDX, // /2
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::None,
                    base: Base::ESP
                }),
                displacement: None,
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 3
            }
        );

        // push esi
        let push: [u8; 2] = [0xFF, 0xF6];
        let call = Instruction::decode(&push, 0);
        assert_eq!(
            call,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xFF),
                    mnemonic_name: MnemonicName::PUSH
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::ESI, // /6
                    rm: RmBits::ESI
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::ESI],
                label: None,
                size: 2
            }
        );
    }

    #[test]
    fn decode_0x81() {
        // add r/m32, imm32; 0x81 /0 id

        // add ebp, 0x11223344
        let add_ebp_imm32: [u8; 6] = [0x81, 0xC5, 0x44, 0x33, 0x22, 0x11];
        let add_ebp_imm32_insn = Instruction::decode(&add_ebp_imm32, 0);
        assert_eq!(
            add_ebp_imm32_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::ADD
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::EBP
                }),
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::EBP, Operand::Imm32(0x11223344)],
                label: None,
                size: 6
            }
        );
        // add [ edx ], 0x11223344
        let add_edx: [u8; 6] = [0x81, 0x02, 0x44, 0x33, 0x22, 0x11];
        let add_edx_insn = Instruction::decode(&add_edx, 0);
        assert_eq!(
            add_edx_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::ADD
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::Mem, Operand::Imm32(0x11223344)],
                label: None,
                size: 6
            }
        );
        // add [ edx + edx*1 + 0x55667788 ], 0x11223344 ; this is how you get edx * 2
        let add_edx_sib: [u8; 11] = [
            0x81, 0x84, 0x12, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        ];
        let add_edx_sib_insn = Instruction::decode(&add_edx_sib, 0);
        assert_eq!(
            add_edx_sib_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::ADD
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::EDX,
                    base: Base::EDX
                }),
                displacement: Some(DisplacementByte::Four(0x55667788)),
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::Mem, Operand::Imm32(0x11223344)],
                label: None,
                size: 11
            }
        );

        // and r/m32, imm32; 0x81 /4 id
        // and [ esp ], 0x05
        let and_esp_mem: [u8; 7] = [0x81, 0x24, 0x24, 0x05, 0x00, 0x00, 0x00];
        let and_esp_insn = Instruction::decode(&and_esp_mem, 0);
        assert_eq!(
            and_esp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::AND
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::ESP, // /4
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::None,
                    base: Base::ESP
                }),
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x05)),
                operands: vec![Operand::Mem, Operand::Imm32(0x05)],
                label: None,
                size: 7
            }
        );

        // cmp r/m32, imm32; 0x81 /7 id
        // cmp esi, 0x11223344
        let cmp: [u8; 6] = [0x81, 0xfe, 0x44, 0x33, 0x22, 0x11];
        let cmp_insn = Instruction::decode(&cmp, 0);
        assert_eq!(
            cmp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::CMP
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EDI, // /7
                    rm: RmBits::ESI
                }),
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::ESI, Operand::Imm32(0x11223344)],
                label: None,
                size: 6
            }
        );

        // or  r/m32, imm32; 0x81 /1 id
        // or esi, 0x11223344
        let or: [u8; 6] = [0x81, 0xce, 0x44, 0x33, 0x22, 0x11];
        let or_insn = Instruction::decode(&or, 0);
        assert_eq!(
            or_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::OR
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::ECX, // /1
                    rm: RmBits::ESI
                }),
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::ESI, Operand::Imm32(0x11223344)],
                label: None,
                size: 6
            }
        );

        // sub r/m32, imm32; 0x81 /5 id
        // sub esi, 0x11223344
        let sub: [u8; 6] = [0x81, 0xee, 0x44, 0x33, 0x22, 0x11];
        let sub_insn = Instruction::decode(&sub, 0);
        assert_eq!(
            sub_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::SUB
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EBP, // /5
                    rm: RmBits::ESI
                }),
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::ESI, Operand::Imm32(0x11223344)],
                label: None,
                size: 6
            }
        );

        // xor r/m32, imm32; 0x81 /6 id
        // xor esi, 0x11223344
        let xor: [u8; 6] = [0x81, 0xf6, 0x44, 0x33, 0x22, 0x11];
        let xor_insn = Instruction::decode(&xor, 0);
        assert_eq!(
            xor_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x81),
                    mnemonic_name: MnemonicName::XOR
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::ESI, // /6
                    rm: RmBits::ESI
                }),
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::ESI, Operand::Imm32(0x11223344)],
                label: None,
                size: 6
            }
        );
    }

    #[test]
    fn decode_accumulators() {
        let and_eax_imm32: [u8; 5] = [0x25, 0x44, 0x33, 0x22, 0x11]; // who's there?
        let and_insn = Instruction::decode(&and_eax_imm32, 0);
        assert_eq!(
            and_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x25),
                    mnemonic_name: MnemonicName::AND,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::EAX, Operand::Imm32(0x11223344)],
                label: None,
                size: 5
            }
        );

        let or_eax_imm32: [u8; 5] = [0x0D, 0x44, 0x33, 0x22, 0x11]; // who's there?
        let or_insn = Instruction::decode(&or_eax_imm32, 0);
        assert_eq!(
            or_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x0D),
                    mnemonic_name: MnemonicName::OR,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::EAX, Operand::Imm32(0x11223344)],
                label: None,
                size: 5
            }
        );
    }

    #[test]
    fn decode_add() {
        let add_eax_imm32: [u8; 5] = [0x05, 0x44, 0x33, 0x22, 0x11]; // who's there?
        let add_insn = Instruction::decode(&add_eax_imm32, 0);
        assert_eq!(
            add_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x05),
                    mnemonic_name: MnemonicName::ADD,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(0x11223344)),
                operands: vec![Operand::EAX, Operand::Imm32(0x11223344)],
                label: None,
                size: 5
            }
        );
    }

    #[test]
    fn decode_nop() {
        let nop: [u8; 2] = [0x90, 0x90]; // who's there?
        let nop_insn = Instruction::decode(&nop, 0);
        assert_eq!(
            nop_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x90),
                    mnemonic_name: MnemonicName::NOP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1
            }
        );
    }

    #[test]
    fn decode_add_01_03() {
        // add [ eax ], esi
        let add: [u8; 2] = [0x01, 0x30];
        let add_insn = Instruction::decode(&add, 0);
        assert_eq!(
            add_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x01),
                    mnemonic_name: MnemonicName::ADD,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::ESI,
                    rm: RmBits::EAX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::Mem, Operand::ESI],
                label: None,
                size: 2
            }
        );

        // add [ ecx + 0x1 ], esi
        let add: [u8; 3] = [0x01, 0x71, 0x01];
        let add_insin = Instruction::decode(&add, 0);
        assert_eq!(
            add_insin,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x01),
                    mnemonic_name: MnemonicName::ADD,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmByte,
                    reg: RegBits::ESI,
                    rm: RmBits::ECX
                }),
                sib: None,
                displacement: Some(DisplacementByte::One(0x01)),
                immediate: None,
                operands: vec![Operand::Mem, Operand::ESI],
                label: None,
                size: 3
            }
        );

        // add [ eax + 0x12345678 ], esi
        let add: [u8; 6] = [0x01, 0xB0, 0x44, 0x33, 0x22, 0x11];
        let add_insin = Instruction::decode(&add, 0);
        assert_eq!(
            add_insin,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x01),
                    mnemonic_name: MnemonicName::ADD,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::ESI,
                    rm: RmBits::EAX
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x11223344)),
                immediate: None,
                operands: vec![Operand::Mem, Operand::ESI],
                label: None,
                size: 6
            }
        );

        // add edx, eax
        let add: [u8; 2] = [0x01, 0xC2];
        let add_insn = Instruction::decode(&add, 0);
        assert_eq!(
            add_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x01),
                    mnemonic_name: MnemonicName::ADD,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // add eax, edx ; flip and use 0x03
        let add: [u8; 2] = [0x03, 0xC2];
        let add_insn = Instruction::decode(&add, 0);
        assert_eq!(
            add_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x03),
                    mnemonic_name: MnemonicName::ADD,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );
    }

    #[test]
    fn decode_01_03_family() {
        // add's 01 and 03 variants are mirrored in...
        // * and 0x21 0x23
        // and edx, eax
        let and: [u8; 2] = [0x21, 0xC2];
        let and_insn = Instruction::decode(&and, 0);
        assert_eq!(
            and_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x21),
                    mnemonic_name: MnemonicName::AND,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // add eax, edx
        let and: [u8; 2] = [0x23, 0xC2];
        let and_insn = Instruction::decode(&and, 0);
        assert_eq!(
            and_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x23),
                    mnemonic_name: MnemonicName::AND,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );

        // * cmp 0x39 0x3B
        // cmp edx, eax
        let mc: [u8; 2] = [0x39, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x39),
                    mnemonic_name: MnemonicName::CMP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // cmp eax, edx
        let mc: [u8; 2] = [0x3B, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x3B),
                    mnemonic_name: MnemonicName::CMP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );

        // * mov 0x89 0x8B
        // mov edx, eax
        let mc: [u8; 2] = [0x89, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x89),
                    mnemonic_name: MnemonicName::MOV,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // mov eax, edx
        let mc: [u8; 2] = [0x8B, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8B),
                    mnemonic_name: MnemonicName::MOV,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );

        // * or  0x09 0x0B
        // or edx, eax
        let mc: [u8; 2] = [0x09, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x09),
                    mnemonic_name: MnemonicName::OR,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // or eax, edx
        let mc: [u8; 2] = [0x0B, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x0B),
                    mnemonic_name: MnemonicName::OR,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );

        // * sub 0x29 0x2B
        // sub edx, eax
        let mc: [u8; 2] = [0x29, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x29),
                    mnemonic_name: MnemonicName::SUB,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // sub eax, edx
        let mc: [u8; 2] = [0x2B, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x2B),
                    mnemonic_name: MnemonicName::SUB,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );

        // * test 0x85 (no inversion)
        let mc: [u8; 2] = [0x85, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x85),
                    mnemonic_name: MnemonicName::TEST,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // * xor 0x31 0x33
        // xor edx, eax
        let mc: [u8; 2] = [0x31, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x31),
                    mnemonic_name: MnemonicName::XOR,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX, Operand::EAX],
                label: None,
                size: 2
            }
        );

        // xor eax, edx
        let mc: [u8; 2] = [0x33, 0xC2];
        let insn = Instruction::decode(&mc, 0);
        assert_eq!(
            insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x33),
                    mnemonic_name: MnemonicName::XOR,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX,
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX, Operand::EDX],
                label: None,
                size: 2
            }
        );
    }

    #[test]
    fn decode_pop_8f() {
        // pop [ eax ]
        let pop_eax_mem: [u8; 2] = [0x8F, 0x00];
        let pop_eax_insn = Instruction::decode(&pop_eax_mem, 0);
        assert_eq!(
            pop_eax_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::EAX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 2
            }
        );

        // pop [ ecx + 0x1 ]
        let pop_ecx: [u8; 3] = [0x8F, 0x41, 0x01];
        let pop_ecx_insn = Instruction::decode(&pop_ecx, 0);
        assert_eq!(
            pop_ecx_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmByte,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::ECX
                }),
                sib: None,
                displacement: Some(DisplacementByte::One(1)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 3
            }
        );

        // pop [ eax + 0x12345678 ]
        let pop_eax_disp32: [u8; 6] = [0x8F, 0x81, 0x78, 0x56, 0x34, 0x12];
        let pop_eax_disp32_insn = Instruction::decode(&pop_eax_disp32, 0);
        assert_eq!(
            pop_eax_disp32_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::ECX
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x12345678)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 6
            }
        );

        // pop edx
        let pop_edx: [u8; 2] = [0x8F, 0xC2];
        let pop_edx_insn = Instruction::decode(&pop_edx, 0);
        assert_eq!(
            pop_edx_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RM,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::EDX
                }),
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX],
                label: None,
                size: 2
            }
        );

        // pop [ esp ]
        let pop_esp_mem: [u8; 3] = [0x8F, 0x04, 0x24];
        let pop_esp_insn = Instruction::decode(&pop_esp_mem, 0);
        assert_eq!(
            pop_esp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::None,
                    base: Base::ESP
                }),
                displacement: None,
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 3
            }
        );

        // pop [ esp + 0x12345678 ]
        let pop_esp_mem: [u8; 7] = [0x8F, 0x84, 0x24, 0x78, 0x56, 0x34, 0x12];
        let pop_esp_insn = Instruction::decode(&pop_esp_mem, 0);
        assert_eq!(
            pop_esp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmDword,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::None,
                    base: Base::ESP
                }),
                displacement: Some(DisplacementByte::Four(0x12345678)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 7
            }
        );

        // pop [ esp + 0x1 ]
        let pop_esp_mem: [u8; 4] = [0x8F, 0x44, 0x24, 0x01];
        let pop_esp_insn = Instruction::decode(&pop_esp_mem, 0);
        assert_eq!(
            pop_esp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmByte,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::SIB
                }),
                sib: Some(SIB {
                    scale: Scale::None,
                    index: Index::None,
                    base: Base::ESP
                }),
                displacement: Some(DisplacementByte::One(0x01)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 4
            }
        );

        // pop [ 0x12345678 ]
        let pop_mem_only: [u8; 6] = [0x8F, 0x05, 0x78, 0x56, 0x34, 0x12];
        let pop_mem_only_insn = Instruction::decode(&pop_mem_only, 0);
        assert_eq!(
            pop_mem_only_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x8F),
                    mnemonic_name: MnemonicName::POP
                }),
                modrm: Some(ModRM {
                    md: MODBits::RmMemory,
                    reg: RegBits::EAX, // /0
                    rm: RmBits::Disp32
                }),
                sib: None,
                displacement: Some(DisplacementByte::Four(0x12345678)),
                immediate: None,
                operands: vec![Operand::Mem],
                label: None,
                size: 6
            }
        );
    }

    #[test]
    fn decode_pop_58() {
        let pop_eax = 0x58u8;
        let pop_eax_insn = Instruction::decode(&[pop_eax], 0);
        assert_eq!(
            pop_eax_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x58),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EAX],
                label: None,
                size: 1
            }
        );

        let pop_ecx = 0x59u8;
        let pop_ecx_insn = Instruction::decode(&[pop_ecx], 0);
        assert_eq!(
            pop_ecx_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x59),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::ECX],
                label: None,
                size: 1
            }
        );

        let pop_edx = 0x5Au8;
        let pop_edx_insn = Instruction::decode(&[pop_edx], 0);
        assert_eq!(
            pop_edx_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x5A),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDX],
                label: None,
                size: 1
            }
        );

        let pop_ebx = 0x5Bu8;
        let pop_ebx_insn = Instruction::decode(&[pop_ebx], 0);
        assert_eq!(
            pop_ebx_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x5B),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EBX],
                label: None,
                size: 1
            }
        );

        let pop_esp = 0x5Cu8;
        let pop_esp_insn = Instruction::decode(&[pop_esp], 0);
        assert_eq!(
            pop_esp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x5C),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::ESP],
                label: None,
                size: 1
            }
        );

        let pop_ebp = 0x5Du8;
        let pop_ebp_insn = Instruction::decode(&[pop_ebp], 0);
        assert_eq!(
            pop_ebp_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x5D),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EBP],
                label: None,
                size: 1
            }
        );

        let pop_esi = 0x5Eu8;
        let pop_esi_insn = Instruction::decode(&[pop_esi], 0);
        assert_eq!(
            pop_esi_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x5E),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::ESI],
                label: None,
                size: 1
            }
        );
        let pop_edi = 0x5Fu8;
        let pop_edi_insn = Instruction::decode(&[pop_edi], 0);
        assert_eq!(
            pop_edi_insn,
            Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x5F),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::EDI],
                label: None,
                size: 1
            }
        );
    }
}

#[cfg(test)]
mod disasm_test {
    use crate::instruction::modrm::{MODBits, ModRM, RegBits, RmBits};
    use crate::instruction::sib::{Base, Index, Scale, SIB};

    #[test]
    fn test_modrm_decoding() {
        let modrm = ModRM::decode(0x84);
        assert_eq!(
            modrm,
            ModRM {
                md: MODBits::RmDword,
                reg: RegBits::EAX, // /0
                rm: RmBits::SIB
            }
        );
        let modrm = ModRM::decode(0x0C);
        assert_eq!(
            modrm,
            ModRM {
                md: MODBits::RmMemory,
                reg: RegBits::ECX,
                rm: RmBits::SIB,
            }
        );
        let modrm = ModRM::decode(0x04);
        assert_eq!(
            modrm,
            ModRM {
                md: MODBits::RmMemory,
                reg: RegBits::EAX, // /0
                rm: RmBits::SIB,
            }
        );

        let modrm = ModRM::decode(0x1D);
        assert_eq!(
            modrm,
            ModRM {
                md: MODBits::RmMemory,
                reg: RegBits::EBX,
                rm: RmBits::Disp32,
            }
        );
    }

    #[test]
    fn test_sib_decoding() {
        let md = MODBits::RmMemory;
        let sib = SIB::decode(0xF7, md);
        assert_eq!(
            sib,
            SIB {
                scale: Scale::Eight,
                index: Index::ESI,
                base: Base::EDI
            }
        );

        let md = MODBits::RmDword;
        let sib = SIB::decode(0xB7, md);
        assert_eq!(
            sib,
            SIB {
                scale: Scale::Four,
                index: Index::ESI,
                base: Base::EDI
            }
        );

        let md = MODBits::RmMemory;
        let sib = SIB::decode(0x6B, md);
        assert_eq!(
            sib,
            SIB {
                scale: Scale::Two,
                index: Index::EBP,
                base: Base::EBX
            }
        );

        let md = MODBits::RmMemory;
        let sib = SIB::decode(0xB5, md);
        assert_eq!(
            sib,
            SIB {
                scale: Scale::Four,
                index: Index::ESI,
                base: Base::Disp32
            }
        );

        let md = MODBits::RmMemory;
        let sib = SIB::decode(0xE4, md);
        assert_eq!(
            sib,
            SIB {
                scale: Scale::Eight, // Note: with Index::None, Scale is irrelevant
                index: Index::None,
                base: Base::ESP
            }
        );
    }
}
