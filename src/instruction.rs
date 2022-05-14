#![allow(clippy::upper_case_acronyms)]

use crate::instruction::modrm::RegBits;
use crate::instruction::sib::{Base, Index, Scale};
use byteorder::{ByteOrder, LittleEndian};
use itertools::Itertools;
use modrm::{MODBits, ModRM, RmBits};
use sib::SIB;
use std::fmt::{Display, Formatter};

pub mod modrm;
pub mod sib;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mnemonic {
    pub(crate) mnemonic_byte: MnemonicByte,
    pub(crate) mnemonic_name: MnemonicName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicName {
    /// special mnemonic to be used when a byte cannot be decoded
    DB,
    ADD,
    AND,
    CALL,
    CLFLUSH,
    CMP,
    DEC,
    IDIV,
    INC,
    JMP,
    JZ,
    JNZ,
    LEA,
    MOV,
    MOVSD, // with repne prefix
    NOP,
    NOT,
    OR,
    POP,
    PUSH,
    CMPSD,
    RETF,
    RETN,
    SUB,
    TEST,
    XOR,
}

impl Display for MnemonicName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MnemonicName::DB => "db",
                MnemonicName::ADD => "add",
                MnemonicName::AND => "and",
                MnemonicName::CALL => "call",
                MnemonicName::CLFLUSH => "clflush",
                MnemonicName::CMP => "cmp",
                MnemonicName::DEC => "dec",
                MnemonicName::IDIV => "idiv",
                MnemonicName::INC => "inc",
                MnemonicName::JMP => "jmp",
                MnemonicName::JZ => "jz",
                MnemonicName::JNZ => "jnz",
                MnemonicName::LEA => "lea",
                MnemonicName::MOV => "mov",
                MnemonicName::MOVSD => "movsd",
                MnemonicName::NOP => "nop",
                MnemonicName::NOT => "not",
                MnemonicName::OR => "or",
                MnemonicName::POP => "pop",
                MnemonicName::PUSH => "push",
                MnemonicName::CMPSD => "cmpsd",
                MnemonicName::RETF => "retf",
                MnemonicName::RETN => "retn",
                MnemonicName::SUB => "sub",
                MnemonicName::TEST => "test",
                MnemonicName::XOR => "xor",
            }
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicByte {
    One(u8),
    Two(u16),
    Three(u32),
}

impl MnemonicByte {
    fn to_byte_str(self) -> String {
        match self {
            MnemonicByte::One(o) => {
                format!("{:02X}", o)
            }
            MnemonicByte::Two(t) => {
                format!("{:04X}", t)
            }
            MnemonicByte::Three(t) => {
                format!("{:06X}", t)
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplacementByte {
    One(u8),
    Two(u16),
    Four(u32),
}

impl DisplacementByte {
    fn to_byte_str(self) -> String {
        match self {
            DisplacementByte::One(o) => {
                format!("{:02X}", o)
            }
            DisplacementByte::Two(t) => {
                format!("{:02X}{:02X}", t & 0xFF, (t >> 8) & 0xFF)
            }
            DisplacementByte::Four(f) => {
                format!(
                    "{:02X}{:02X}{:02X}{:02X}",
                    f & 0xFF,
                    (f >> 8) & 0xFF,
                    (f >> 16) & 0xFF,
                    (f >> 24) & 0xFF,
                )
            }
        }
    }

    fn to_u32(self) -> u32 {
        match self {
            DisplacementByte::One(u) => u as u32,
            DisplacementByte::Two(u) => u as u32,
            DisplacementByte::Four(u) => u,
        }
    }

    #[allow(dead_code)]
    fn to_u8(self) -> u8 {
        match self {
            DisplacementByte::One(u) => u,
            DisplacementByte::Two(u) => u as u8,
            DisplacementByte::Four(u) => u as u8,
        }
    }

    fn to_i32(self) -> i32 {
        match self {
            DisplacementByte::One(u) => u as i8 as i32,
            DisplacementByte::Two(u) => u as i16 as i32,
            DisplacementByte::Four(u) => u as i32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmediateByte {
    One(u8),
    Two(u16),
    Four(u32),
}

impl ImmediateByte {
    fn to_byte_str(self) -> String {
        match self {
            ImmediateByte::One(o) => {
                format!("{:02X}", o)
            }
            ImmediateByte::Two(t) => {
                format!("{:02X}{:02X}", t & 0xFF, (t >> 8) & 0xFF)
            }
            ImmediateByte::Four(f) => {
                format!(
                    "{:02X}{:02X}{:02X}{:02X}",
                    f & 0xFF,
                    (f >> 8) & 0xFF,
                    (f >> 16) & 0xFF,
                    (f >> 24) & 0xFF,
                )
            }
        }
    }
}

impl From<u8> for Operand {
    fn from(byte: u8) -> Self {
        match byte {
            0x0 => Operand::EAX,
            0x1 => Operand::ECX,
            0x2 => Operand::EDX,
            0x3 => Operand::EBX,
            0x4 => Operand::ESP,
            0x5 => Operand::EBP,
            0x6 => Operand::ESI,
            0x7 => Operand::EDI,
            _ => Operand::Byte(byte), // it's really better to make this directly instead of
                                      // relying on decoding, in case the byte has a low value
        }
    }
}

impl From<u32> for Operand {
    fn from(dword: u32) -> Self {
        Operand::Dword(dword)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    Byte(u8),
    Dword(u32),
    Imm8(u8),
    Imm16(u16),
    Imm32(u32),
    Mem, // indicates we must check the modrm, sib, etc to see how to display this operand
}

impl Display for Operand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Operand::EAX => "eax".to_string(),
                Operand::ECX => "ecx".to_string(),
                Operand::EDX => "edx".to_string(),
                Operand::EBX => "ebx".to_string(),
                Operand::ESP => "esp".to_string(),
                Operand::EBP => "ebp".to_string(),
                Operand::ESI => "esi".to_string(),
                Operand::EDI => "edi".to_string(),
                Operand::Byte(v) => {
                    format!("{:#010X}", *v as i8 as i32)
                }
                Operand::Dword(v) => {
                    format!("{:#010X}", v)
                }
                Operand::Imm8(v) => {
                    format!("{:#010X}", *v as i8 as i32)
                }
                Operand::Imm16(v) => {
                    format!("{:#010X}", *v as i16 as i32)
                }
                Operand::Imm32(v) => {
                    format!("{:#010X}", v)
                }
                Operand::Mem => "mem".to_string(),
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefix {
    REPNE,
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Prefix::REPNE => "repne",
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub(crate) name: String,
    pub(crate) displacement: isize,
    pub(crate) index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Instruction {
    pub(crate) prefix: Option<Prefix>,
    pub(crate) mnemonic: Option<Mnemonic>,
    pub(crate) modrm: Option<ModRM>,
    pub(crate) sib: Option<SIB>,
    pub(crate) displacement: Option<DisplacementByte>,
    pub(crate) immediate: Option<ImmediateByte>,
    pub(crate) operands: Vec<Operand>,
    pub(crate) label: Option<Label>,
    pub(crate) size: usize,
}

fn operands_to_string(operands: &Vec<Operand>, insn: &Instruction) -> String {
    let mut ops: Vec<String> = vec![];
    for op in operands {
        if op != &Operand::Mem {
            ops.push(op.to_string())
        } else {
            let mut mem: Vec<String> = vec!["[".to_string()];
            if let Some(modrm) = insn.modrm {
                match modrm.md {
                    MODBits::RmMemory => {
                        mem.push(modrm.rm.to_string());
                        if modrm.rm == RmBits::Disp32 {
                            if let Some(disp) = insn.displacement {
                                mem.push(format!("{:#010X}", disp.to_u32()))
                            }
                        }
                        if modrm.rm == RmBits::SIB {
                            if let Some(sib) = insn.sib {
                                mem.push(
                                    (match sib.index {
                                        Index::EAX => "eax",
                                        Index::ECX => "ecx",
                                        Index::EDX => "edx",
                                        Index::EBX => "ebx",
                                        Index::None => "",
                                        Index::EBP => "ebp",
                                        Index::ESI => "esi",
                                        Index::EDI => "edi",
                                    })
                                    .to_string(),
                                );
                                mem.push(
                                    (match sib.scale {
                                        Scale::None => "",
                                        Scale::Two => "*2",
                                        Scale::Four => "*4",
                                        Scale::Eight => "*8",
                                    })
                                    .to_string(),
                                );

                                mem.push(
                                    (match sib.base {
                                        Base::EAX => " + eax",
                                        Base::ECX => " + ecx",
                                        Base::EDX => " + edx",
                                        Base::EBX => " + ebx",
                                        Base::ESP => " + esp",
                                        Base::Disp32 => "",
                                        Base::EBP => " + ebp",
                                        Base::ESI => " + esi",
                                        Base::EDI => " + edi",
                                    })
                                    .to_string(),
                                );

                                if sib.base == Base::Disp32 {
                                    if let Some(disp) = insn.displacement {
                                        // this should only ever be an imm32
                                        mem.push(format!("{:#010X}", disp.to_u32()))
                                    }
                                }
                            }
                        }
                    }
                    MODBits::RmByte | MODBits::RmDword => {
                        if modrm.rm != RmBits::SIB {
                            mem.push(format!("{}", modrm.rm));
                        } else if let Some(sib) = insn.sib {
                            mem.push(
                                (match sib.index {
                                    Index::EAX => "eax",
                                    Index::ECX => "ecx",
                                    Index::EDX => "edx",
                                    Index::EBX => "ebx",
                                    Index::None => "",
                                    Index::EBP => "ebp",
                                    Index::ESI => "esi",
                                    Index::EDI => "edi",
                                })
                                .to_string(),
                            );
                            mem.push(
                                (match sib.scale {
                                    Scale::None => "",
                                    Scale::Two => "*2",
                                    Scale::Four => "*4",
                                    Scale::Eight => "*8",
                                })
                                .to_string(),
                            );

                            mem.push(
                                (match sib.base {
                                    Base::EAX => " + eax",
                                    Base::ECX => " + ecx",
                                    Base::EDX => " + edx",
                                    Base::EBX => " + ebx",
                                    Base::ESP => " + esp",
                                    Base::Disp32 => "",
                                    Base::EBP => " + ebp",
                                    Base::ESI => " + esi",
                                    Base::EDI => " + edi",
                                })
                                .to_string(),
                            );
                        }
                        if let Some(disp) = insn.displacement {
                            if mem.len() > 1 {
                                if modrm.md == MODBits::RmByte {
                                    //mem.push(format!("+ {:#04X}", disp.to_u8()))
                                    mem.push(format!("+ {:#010X}", disp.to_i32()))
                                } else {
                                    mem.push(format!("+ {:#010X}", disp.to_u32()))
                                }
                            } else {
                                // this should only ever be an imm32
                                mem.push(format!("{:#010X}", disp.to_u32()))
                            }
                        }
                    }
                    MODBits::RM => {
                        // To get here, we need to have a Mem operand. We can't have a Mem
                        // operand in RM mode (0b11).
                        unreachable!()
                    }
                }
            }
            mem.push("]".to_string());
            ops.push(mem.join(" "));
        }
    }
    ops.iter().format(", ").to_string()
}

impl Display for Instruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        //println!("{:#?}", self);
        let mnemonic = self.mnemonic.unwrap_or(Mnemonic {
            mnemonic_byte: MnemonicByte::One(0),
            mnemonic_name: MnemonicName::DB,
        });
        write!(
            f,
            "{} {}",
            if let Some(prefix) = self.prefix {
                format!("{} {}", prefix, mnemonic.mnemonic_name)
            } else {
                mnemonic.mnemonic_name.to_string()
            },
            operands_to_string(&self.operands, self)
        )
    }
}

impl Instruction {
    pub(crate) fn to_labeled_string(&self) -> String {
        //println!("{:#?}", self);
        let mnemonic = self.mnemonic.unwrap_or(Mnemonic {
            mnemonic_byte: MnemonicByte::One(0),
            mnemonic_name: MnemonicName::DB,
        });
        let label = if let Some(label) = &self.label {
            label.clone()
        } else {
            Label {
                name: "offset_00000000h".to_string(),
                displacement: 0,
                index: 0,
            }
        };
        format!("{} {}", mnemonic.mnemonic_name, label.name)
    }
    /// Returns Instruction, the next index
    pub(crate) fn decode(bytes: &[u8], idx: usize) -> Instruction {
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

        if idx >= bytes.len() {
            return Instruction {
                prefix: None,
                mnemonic: None,
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 0,
            };
        }

        let byte = bytes[idx];

        match byte {
            //------------
            // `add` [and, cmp, or, sub, xor]
            //------------

            // add eax, imm32 ; 0x05 id
            0x05 => Self::accumulate(bytes, idx, byte, MnemonicName::ADD),

            // add r/m32, imm32; 0x81 /0 id
            // and r/m32, imm32; 0x81 /4 id
            // cmp r/m32, imm32; 0x81 /7 id
            // or  r/m32, imm32; 0x81 /1 id
            // sub r/m32, imm32; 0x81 /5 id
            // xor r/m32, imm32; 0x81 /6 id
            0x81 => {
                let mut size = 2;
                // decode modrm
                let modrm = ModRM::decode(bytes[idx + 1]);

                // determine the mnemonic
                let mnemonic_byte = MnemonicByte::One(0x81);
                let mnemonic = Some(match modrm.reg.to_byte() {
                    0 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::ADD,
                    },
                    1 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::OR,
                    },
                    4 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::AND,
                    },
                    5 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::SUB,
                    },
                    6 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::XOR,
                    },
                    7 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::CMP,
                    },
                    _ => return default(byte),
                });
                // if we have a SIB
                let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                size += size_;
                // if we have a displacement
                let (displacement, size_) = Self::decode_displacement(bytes, idx, modrm, size, sib);
                size += size_;
                size += 4; // imm32
                Instruction {
                    prefix: None,
                    mnemonic,
                    modrm: Some(modrm),
                    sib,
                    displacement,
                    immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                        &bytes[idx + size - 4..idx + size],
                    ))),
                    operands: vec![
                        if modrm.md == MODBits::RM {
                            Operand::from(modrm.rm.to_byte())
                        } else {
                            Operand::Mem
                        },
                        Operand::Imm32(LittleEndian::read_u32(&bytes[idx + size - 4..idx + size])),
                    ],
                    label: None,
                    size,
                }
            }

            // add r/m32, r32; 0x01 /r
            0x01 => Self::parse_01_family(bytes, idx, MnemonicName::ADD),

            // add r32, r/m32; 0x03 /r
            0x03 => Self::parse_03_family(bytes, idx, MnemonicName::ADD),

            //------------
            // `and`
            //------------

            // and eax, imm32
            0x25 => Self::accumulate(bytes, idx, byte, MnemonicName::AND),

            // and r/m32, r32; 0x21 /r
            0x21 => Self::parse_01_family(bytes, idx, MnemonicName::AND),

            // and r32, r/m32; 0x23 /r
            0x23 => Self::parse_03_family(bytes, idx, MnemonicName::AND),

            //------------
            // `call`
            //------------
            0xFF => {
                // 0xff family
                // call r/m32; /2
                // dec  r/m32; /1
                // inc  r/m32; /0
                // jmp  r/m32; /4
                // push r/m32; /6
                let mut size = 2;
                // decode modrm
                let modrm = ModRM::decode(bytes[idx + 1]);

                // determine the mnemonic
                let mnemonic_byte = MnemonicByte::One(0xFF);
                let mnemonic = Some(match modrm.reg.to_byte() {
                    0 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::INC,
                    },
                    1 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::DEC,
                    },
                    // Since this is a call r/m32, we cannot assign a label.
                    2 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::CALL,
                    },
                    // Since this is a jmp r/m32, we cannot assign a label.
                    4 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::JMP,
                    },
                    6 => Mnemonic {
                        mnemonic_byte,
                        mnemonic_name: MnemonicName::PUSH,
                    },
                    _ => return default(byte),
                });
                // if we have a SIB
                let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                size += size_;
                // if we have a displacement
                let (displacement, size_) = Self::decode_displacement(bytes, idx, modrm, size, sib);
                size += size_;
                Instruction {
                    prefix: None,
                    mnemonic,
                    modrm: Some(modrm),
                    sib,
                    displacement,
                    immediate: None,
                    operands: vec![if modrm.md == MODBits::RM {
                        Operand::from(modrm.rm.to_byte())
                    } else {
                        Operand::Mem
                    }],
                    label: None,
                    size,
                }
            }

            // call rel32
            0xE8 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xE8),
                    mnemonic_name: MnemonicName::CALL,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))),
                operands: vec![Operand::Imm32(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))],
                label: Some(Label {
                    name: format!(
                        "offset_{:#010X}h",
                        idx as i32 + 5 + LittleEndian::read_i32(&bytes[idx + 1..=idx + 4],)
                    ),
                    displacement: LittleEndian::read_i32(&bytes[idx + 1..=idx + 4]) as isize,
                    // it's relative to the END of the instruction, so add size to idx
                    index: idx + 5,
                }),
                size: 5,
            },

            //------------
            // `clflush`
            //------------
            // 0x0F 0xAE /7 ; clflush m8
            // 0x0F 0x84 cd ; jz rel32
            // 0x0F 0x85 cd ; jnz rel32
            0x0F => match bytes[idx + 1] {
                // clflush
                0xAE => {
                    let modrm = ModRM::decode(bytes[idx + 2]);
                    // addressing mode 11 is not allowed for clflush
                    if modrm.md == MODBits::RM {
                        return default(byte);
                    }
                    // clflush requires /7
                    if modrm.reg != RegBits::EDI {
                        return default(byte);
                    }
                    let (sib, size_) = Self::decode_sib(bytes, idx + 1, modrm);
                    let mut size = 3 + size_;
                    let (displacement, size_) =
                        Self::decode_displacement(bytes, idx, modrm, size, sib);
                    size += size_;
                    Instruction {
                        prefix: None,
                        mnemonic: Some(Mnemonic {
                            mnemonic_byte: MnemonicByte::Two(0x0FAE),
                            mnemonic_name: MnemonicName::CLFLUSH,
                        }),
                        modrm: Some(modrm),
                        sib,
                        displacement,
                        immediate: None,
                        operands: vec![Operand::Mem],
                        label: None,
                        size,
                    }
                }
                // jz, jnz
                0x84 | 0x85 => {
                    // A relative offset (rel8, rel16, or rel32) is generally specified
                    // as a label in assembly code, but at the machine code level, it is
                    // encoded as a signed, 8-bit or 32-bit immediate value, which is
                    // added to the instruction pointer.
                    let b = bytes[idx + 1];
                    Instruction {
                        prefix: None,
                        mnemonic: Some(Mnemonic {
                            mnemonic_byte: MnemonicByte::Two(if b == 0x84 {
                                0x0F84
                            } else {
                                0x0F85
                            }),
                            mnemonic_name: if b == 0x84 {
                                MnemonicName::JZ
                            } else {
                                MnemonicName::JNZ
                            },
                        }),
                        modrm: None,
                        sib: None,
                        displacement: None,
                        immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                            &bytes[idx + 2..idx + 6],
                        ))),
                        operands: vec![Operand::Imm32(LittleEndian::read_u32(
                            &bytes[idx + 2..idx + 6],
                        ))],
                        label: Some(Label {
                            name: format!(
                                "offset_{:#010X}h",
                                idx as i32 + 6 + LittleEndian::read_i32(&bytes[idx + 2..=idx + 5],)
                            ),
                            displacement: LittleEndian::read_i32(&bytes[idx + 2..=idx + 5])
                                as isize,
                            // it's relative to the END of the instruction, so add size to idx
                            index: idx + 6,
                        }),
                        size: 6,
                    }
                }
                _ => default(byte),
            },

            //------------
            // `cmp`
            //------------
            // cmp eax, imm32
            0x3D => Self::accumulate(bytes, idx, byte, MnemonicName::CMP),

            // cmp r/m32, r32; 0x39 /r
            0x39 => Self::parse_01_family(bytes, idx, MnemonicName::CMP),

            // cmp r32, r/m32; 0x3B /r
            0x3B => Self::parse_03_family(bytes, idx, MnemonicName::CMP),

            //------------
            // `dec`
            //------------

            // dec r32
            0x48..=0x4F => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(byte),
                    mnemonic_name: MnemonicName::DEC,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::from(byte - 0x48)],
                label: None,
                size: 1,
            },

            //------------
            // `idiv`
            //------------

            // idiv r/m32 ; /7
            // not r/m32 ; /2
            // test r/m32, imm32 ; /0 id
            0xF7 => {
                let modrm = ModRM::decode(bytes[idx + 1]);
                match modrm.reg.to_byte() {
                    // test
                    0 => {
                        let mut size = 2;
                        let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                        size += size_;
                        let (displacement, size_) =
                            Self::decode_displacement(bytes, idx, modrm, size, sib);
                        size += size_;
                        size += 4; // imm32

                        Instruction {
                            prefix: None,
                            mnemonic: Some(Mnemonic {
                                mnemonic_byte: MnemonicByte::One(0xF7),
                                mnemonic_name: MnemonicName::TEST,
                            }),
                            modrm: Some(modrm),
                            sib,
                            displacement,
                            immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                                &bytes[idx + size - 4..idx + size],
                            ))),
                            operands: vec![
                                if modrm.md == MODBits::RM {
                                    Operand::from(modrm.rm.to_byte())
                                } else {
                                    Operand::Mem
                                },
                                Operand::Imm32(LittleEndian::read_u32(
                                    &bytes[idx + size - 4..idx + size],
                                )),
                            ],
                            label: None,
                            size,
                        }
                    }
                    // not, 2
                    // idiv, 7
                    2 | 7 => {
                        let mut size = 2;
                        let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                        size += size_;
                        let (displacement, size_) =
                            Self::decode_displacement(bytes, idx, modrm, size, sib);
                        size += size_;

                        Instruction {
                            prefix: None,
                            mnemonic: Some(Mnemonic {
                                mnemonic_byte: MnemonicByte::One(0xF7),
                                mnemonic_name: if modrm.reg.to_byte() == 2 {
                                    MnemonicName::NOT
                                } else {
                                    MnemonicName::IDIV
                                },
                            }),
                            modrm: Some(modrm),
                            sib,
                            displacement,
                            immediate: None,
                            // Anything that's not a direct reg access here is MEM, which encodes
                            // operands already.
                            operands: if modrm.md == MODBits::RM {
                                vec![Operand::from(modrm.rm.to_byte())]
                            } else {
                                vec![Operand::Mem]
                            },
                            label: None,
                            size,
                        }
                    }
                    _ => default(byte),
                }
            }

            //------------
            // `inc`
            //------------
            0x40..=0x47 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(byte),
                    mnemonic_name: MnemonicName::INC,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::from(byte - 0x40)],
                label: None,
                size: 1,
            },

            //------------
            // `jmp`
            //------------

            // jmp rel8
            0xEB => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xEB),
                    mnemonic_name: MnemonicName::JMP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::One(bytes[idx + 1])),
                operands: vec![Operand::Imm8(bytes[idx + 1])],
                label: Some(Label {
                    name: format!(
                        "offset_{:#010X}h",
                        idx as i32 + 2 + bytes[idx + 1] as i8 as i32,
                    ),
                    displacement: (bytes[idx + 1] as i8) as isize,
                    // it's relative to the END of the instruction, so add size to idx
                    index: idx + 2,
                }),
                size: 2,
            },

            // jmp rel32
            0xE9 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xE9),
                    mnemonic_name: MnemonicName::JMP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))),
                operands: vec![Operand::Imm32(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))],
                label: Some(Label {
                    name: format!(
                        "offset_{:#010X}h",
                        idx as i32 + 5 + LittleEndian::read_i32(&bytes[idx + 1..=idx + 4],)
                    ),
                    displacement: LittleEndian::read_i32(&bytes[idx + 1..=idx + 4]) as isize,
                    // it's relative to the END of the instruction, so add size to idx
                    index: idx + 5,
                }),
                size: 5,
            },

            //------------
            // `jz`
            //------------
            0x74 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x74),
                    mnemonic_name: MnemonicName::JZ,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::One(bytes[idx + 1])),
                operands: vec![Operand::Imm8(bytes[idx + 1])],
                label: Some(Label {
                    name: format!(
                        "offset_{:#010X}h",
                        idx as i32 + 2 + bytes[idx + 1] as i8 as i32,
                    ),
                    displacement: bytes[idx + 1] as i8 as isize,
                    // it's relative to the END of the instruction, so add size to idx
                    index: idx + 2,
                }),
                size: 2,
            },

            //------------
            // `jnz`
            //------------
            0x75 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x75),
                    mnemonic_name: MnemonicName::JNZ,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::One(bytes[idx + 1])),
                operands: vec![Operand::Imm8(bytes[idx + 1])],
                label: Some(Label {
                    name: format!(
                        "offset_{:#010X}h",
                        idx as i32 + 2 + bytes[idx + 1] as i8 as i32,
                    ),
                    displacement: bytes[idx + 1] as i8 as isize,
                    // it's relative to the END of the instruction, so add size to idx
                    index: idx + 2,
                }),
                size: 2,
            },

            //------------
            // `lea`
            //------------
            0x8D => {
                let modrm = ModRM::decode(bytes[idx + 1]);
                if modrm.md == MODBits::RM {
                    // addressing mode 11 is not valid for this instruction
                    return default(byte);
                }
                let mut size = 2;
                let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                size += size_;
                let (displacement, size_) = Self::decode_displacement(bytes, idx, modrm, size, sib);
                size += size_;
                Instruction {
                    prefix: None,
                    mnemonic: Some(Mnemonic {
                        mnemonic_byte: MnemonicByte::One(0x8D),
                        mnemonic_name: MnemonicName::LEA,
                    }),
                    modrm: Some(modrm),
                    sib,
                    displacement,
                    immediate: None,
                    operands: vec![Operand::from(modrm.reg.to_byte()), Operand::Mem],
                    label: None,
                    size,
                }
            }

            //------------
            // `mov`
            //------------
            // mov r/m32, r32; 0x89 /r
            0x89 => Self::parse_01_family(bytes, idx, MnemonicName::MOV),

            // mov r32, r/m32; 0x8B /r
            0x8B => Self::parse_03_family(bytes, idx, MnemonicName::MOV),

            // mov r32, imm32; 0xB8 + rd id
            0xB8..=0xBF => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(byte),
                    mnemonic_name: MnemonicName::MOV,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))),
                operands: vec![
                    Operand::from(byte - 0xB8),
                    Operand::Imm32(LittleEndian::read_u32(&bytes[idx + 1..=idx + 4])),
                ],
                label: None,
                size: 5,
            },

            // mov r/m32, imm32; 0xC7 /0
            0xC7 => {
                // There are no other C7 instructions in scope, otherwise they'd go in here
                let modrm = ModRM::decode(bytes[idx + 1]);
                if modrm.reg != RegBits::EAX {
                    return default(byte);
                }

                let mut size = 2;
                let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                size += size_;
                // if we have a displacement
                let (displacement, size_) = Self::decode_displacement(bytes, idx, modrm, size, sib);
                size += size_;
                size += 4; // imm32
                Instruction {
                    prefix: None,
                    mnemonic: Some(Mnemonic {
                        mnemonic_byte: MnemonicByte::One(0xC7),
                        mnemonic_name: MnemonicName::MOV,
                    }),
                    modrm: Some(modrm),
                    sib,
                    displacement,
                    immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                        &bytes[idx + size - 4..idx + size],
                    ))),
                    operands: vec![
                        if modrm.md == MODBits::RM {
                            Operand::from(modrm.rm.to_byte())
                        } else {
                            Operand::Mem
                        },
                        Operand::Imm32(LittleEndian::read_u32(&bytes[idx + size - 4..idx + size])),
                    ],
                    label: None,
                    size,
                }
            }

            //------------
            // `movsd`
            //------------
            0xA5 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xA5),
                    mnemonic_name: MnemonicName::MOVSD,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1,
            },

            //------------
            // `nop`
            //------------
            0x90 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(byte),
                    mnemonic_name: MnemonicName::NOP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![], // no operands
                label: None,
                size: 1,
            },

            //------------
            // `not`
            //------------

            // these were taken care of in other families

            //------------
            // `or`
            //------------
            // or eax, imm32
            0x0D => Self::accumulate(bytes, idx, byte, MnemonicName::OR),

            // or r/m32, r32; 0x09 /r
            0x09 => Self::parse_01_family(bytes, idx, MnemonicName::OR),

            // or r32, r/m32; 0x0B /r
            0x0B => Self::parse_03_family(bytes, idx, MnemonicName::OR),

            //------------
            // `pop`
            //------------

            // 0x58; pop eax through pop edi
            0x58..=0x5f => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(byte),
                    mnemonic_name: MnemonicName::POP,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::from(byte - 0x58)],
                label: None,
                size: 1,
            },
            // 0x8f /0; pop
            0x8f => {
                let modrm = ModRM::decode(bytes[idx + 1]);
                if modrm.reg.to_byte() == 0 {
                    let mut size = 2;
                    let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
                    size += size_;
                    let (displacement, size_) =
                        Self::decode_displacement(bytes, idx, modrm, size, sib);
                    size += size_;
                    Instruction {
                        prefix: None,
                        mnemonic: Some(Mnemonic {
                            // Do not count MODRM as part of the mnemonic, since we can recover that
                            // later.
                            mnemonic_byte: MnemonicByte::One(0x8F),
                            mnemonic_name: MnemonicName::POP,
                        }),
                        modrm: Some(modrm),
                        sib,
                        displacement,
                        immediate: None,
                        // Anything that's not a direct reg access here is MEM, which encodes
                        // operands already.
                        operands: if modrm.md == MODBits::RM {
                            vec![Operand::from(modrm.rm.to_byte())]
                        } else {
                            vec![Operand::Mem]
                        },
                        label: None,
                        size,
                    }
                } else {
                    default(byte)
                }
            }

            //------------
            // `push`
            //------------
            0x50..=0x57 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(byte),
                    mnemonic_name: MnemonicName::PUSH,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![Operand::from(byte - 0x50)],
                label: None,
                size: 1,
            },

            0x68 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0x68),
                    mnemonic_name: MnemonicName::PUSH,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))),
                operands: vec![Operand::Imm32(LittleEndian::read_u32(
                    &bytes[idx + 1..=idx + 4],
                ))],
                label: None,
                size: 5,
            },

            //------------
            // `repne cmpsd`
            //------------
            0xF2 => {
                if bytes[idx + 1] != 0xA7 {
                    // we only care about cmpsd with repne prefix
                    return default(byte);
                }

                Instruction {
                    prefix: Some(Prefix::REPNE),
                    mnemonic: Some(Mnemonic {
                        // special casing this due to prefix
                        mnemonic_byte: MnemonicByte::One(0xA7),
                        mnemonic_name: MnemonicName::CMPSD,
                    }),
                    modrm: None,
                    sib: None,
                    displacement: None,
                    immediate: None,
                    operands: vec![],
                    label: None,
                    size: 2,
                }
            }
            //------------
            // `retf`
            //------------

            // retf
            0xCB => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xCB),
                    mnemonic_name: MnemonicName::RETF,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1,
            },
            // retf imm16
            0xCA => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xCA),
                    mnemonic_name: MnemonicName::RETF,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Two(LittleEndian::read_u16(
                    &bytes[idx + 1..=idx + 2],
                ))),
                operands: vec![Operand::Imm16(LittleEndian::read_u16(
                    &bytes[idx + 1..=idx + 2],
                ))],
                label: None,
                size: 3,
            },

            //------------
            // `retn`
            //------------

            // retn
            0xC3 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xC3),
                    mnemonic_name: MnemonicName::RETN,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: None,
                operands: vec![],
                label: None,
                size: 1,
            },

            // retn imm16
            0xC2 => Instruction {
                prefix: None,
                mnemonic: Some(Mnemonic {
                    mnemonic_byte: MnemonicByte::One(0xC2),
                    mnemonic_name: MnemonicName::RETN,
                }),
                modrm: None,
                sib: None,
                displacement: None,
                immediate: Some(ImmediateByte::Two(LittleEndian::read_u16(
                    &bytes[idx + 1..=idx + 2],
                ))),
                operands: vec![Operand::Imm16(LittleEndian::read_u16(
                    &bytes[idx + 1..=idx + 2],
                ))],
                label: None,
                size: 3,
            },

            //------------
            // `sub`
            //------------
            // sub eax, imm32
            0x2D => Self::accumulate(bytes, idx, byte, MnemonicName::SUB),

            // sub r/m32, r32; 0x29 /r
            0x29 => Self::parse_01_family(bytes, idx, MnemonicName::SUB),

            // sub r32, r/m32; 0x2B /r
            0x2B => Self::parse_03_family(bytes, idx, MnemonicName::SUB),

            //------------
            // `test`
            //------------
            // test eax, imm32
            0xA9 => Self::accumulate(bytes, idx, byte, MnemonicName::TEST),

            // test r/m32, r32; 0x85 /r
            0x85 => Self::parse_01_family(bytes, idx, MnemonicName::TEST),

            //------------
            // `xor`
            //------------
            // test eax, imm32
            0x35 => Self::accumulate(bytes, idx, byte, MnemonicName::XOR),

            // xor r/m32, r32; 0x31 /r
            0x31 => Self::parse_01_family(bytes, idx, MnemonicName::XOR),

            // xor r32, r/m32; 0x33 /r
            0x33 => Self::parse_03_family(bytes, idx, MnemonicName::XOR),

            //------------
            // `db` [default return if no match]
            //------------
            _ => default(byte),
        }
    }

    fn accumulate(bytes: &[u8], idx: usize, byte: u8, mnemonic_name: MnemonicName) -> Instruction {
        Instruction {
            prefix: None,
            mnemonic: Some(Mnemonic {
                mnemonic_byte: MnemonicByte::One(byte),
                mnemonic_name,
            }),
            modrm: None,
            sib: None,
            displacement: None,
            immediate: Some(ImmediateByte::Four(LittleEndian::read_u32(
                &bytes[idx + 1..=idx + 4],
            ))),
            operands: vec![
                Operand::EAX,
                Operand::Imm32(LittleEndian::read_u32(&bytes[idx + 1..=idx + 4])),
            ],
            label: None,
            size: 5,
        }
    }

    fn parse_03_family(bytes: &[u8], idx: usize, mnemonic_name: MnemonicName) -> Instruction {
        let modrm = ModRM::decode(bytes[idx + 1]);
        let mut size = 2;
        let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
        size += size_;
        let (displacement, size_) = Self::decode_displacement(bytes, idx, modrm, size, sib);
        size += size_;
        Instruction {
            prefix: None,
            mnemonic: Some(Mnemonic {
                mnemonic_byte: MnemonicByte::One(bytes[idx]),
                mnemonic_name,
            }),
            modrm: Some(modrm),
            sib,
            displacement,
            immediate: None,
            operands: vec![
                Operand::from(modrm.reg.to_byte()),
                if modrm.md == MODBits::RM {
                    Operand::from(modrm.rm.to_byte())
                } else {
                    Operand::Mem
                },
            ],
            label: None,
            size,
        }
    }

    fn parse_01_family(bytes: &[u8], idx: usize, mnemonic_name: MnemonicName) -> Instruction {
        let modrm = ModRM::decode(bytes[idx + 1]);
        let mut size = 2;
        let (sib, size_) = Self::decode_sib(bytes, idx, modrm);
        size += size_;
        let (displacement, size_) = Self::decode_displacement(bytes, idx, modrm, size, sib);
        size += size_;
        Instruction {
            prefix: None,
            mnemonic: Some(Mnemonic {
                mnemonic_byte: MnemonicByte::One(bytes[idx]),
                mnemonic_name,
            }),
            modrm: Some(modrm),
            sib,
            displacement,
            immediate: None,
            operands: vec![
                if modrm.md == MODBits::RM {
                    Operand::from(modrm.rm.to_byte())
                } else {
                    Operand::Mem
                },
                Operand::from(modrm.reg.to_byte()),
            ],
            label: None,
            size,
        }
    }

    fn decode_displacement(
        bytes: &[u8],
        idx: usize,
        modrm: ModRM,
        size: usize,
        sib: Option<SIB>,
    ) -> (Option<DisplacementByte>, usize) {
        if modrm.rm == RmBits::Disp32 {
            (
                Some(DisplacementByte::Four(LittleEndian::read_u32(
                    &bytes[idx + size..idx + size + 4],
                ))),
                4,
            )
        } else {
            match modrm.md {
                MODBits::RmMemory => {
                    if let Some(sib) = sib {
                        match sib.base {
                            Base::Disp32 => (
                                Some(DisplacementByte::Four(LittleEndian::read_u32(
                                    &bytes[idx + size..idx + size + 4],
                                ))),
                                4,
                            ),
                            _ => (None, 0),
                        }
                    } else {
                        (None, 0)
                    }
                }
                MODBits::RmByte => (Some(DisplacementByte::One(bytes[idx + size])), 1),
                MODBits::RmDword => (
                    Some(DisplacementByte::Four(LittleEndian::read_u32(
                        &bytes[idx + size..idx + size + 4],
                    ))),
                    4,
                ),
                MODBits::RM => (None, 0),
            }
        }
    }

    fn decode_sib(bytes: &[u8], idx: usize, modrm: ModRM) -> (Option<SIB>, usize) {
        if modrm.rm == RmBits::SIB {
            (Some(SIB::decode(bytes[idx + 2], modrm.md)), 1)
        } else {
            (None, 0)
        }
    }

    pub(crate) fn get_bytes_string(&self) -> String {
        let prefix = match self.prefix {
            Some(p) => match p {
                Prefix::REPNE => "F2",
            },
            None => "",
        };

        let mnemonic = match self.mnemonic {
            None => "".to_string(),
            Some(m) => m.mnemonic_byte.to_byte_str(),
        };

        let modrm = match self.modrm {
            None => "".to_string(),
            Some(m) => m.to_byte_str(),
        };
        let sib = match self.sib {
            None => "".to_string(),
            Some(s) => s.to_byte_str(),
        };
        let displacement = match self.displacement {
            None => "".to_string(),
            Some(d) => d.to_byte_str(),
        };
        let immediate = match self.immediate {
            None => "".to_string(),
            Some(i) => i.to_byte_str(),
        };

        format!(
            "{}{}{}{}{}{}",
            prefix, mnemonic, modrm, sib, displacement, immediate
        )
    }
}
