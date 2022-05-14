use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MODBits {
    RmMemory, // 0b00
    RmByte,   // 0b01
    RmDword,  // 0b10
    RM,       // 0b11
}

impl Display for RmBits {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RmBits::EAX => "eax",
                RmBits::ECX => "ecx",
                RmBits::EDX => "edx",
                RmBits::EBX => "ebx",
                RmBits::SIB => "",
                RmBits::EBP => "ebp",
                RmBits::Disp32 => "",
                RmBits::ESP => "esp",
                RmBits::ESI => "esi",
                RmBits::EDI => "edi",
            }
        )
    }
}

impl From<u8> for MODBits {
    fn from(modrm_byte: u8) -> Self {
        match (modrm_byte & 0b11000000) >> 6 {
            0b00 => MODBits::RmMemory, // [ reg ] OR SIB OR disp32
            0b01 => MODBits::RmByte,   // [ reg + byte] OR SIB + byte
            0b10 => MODBits::RmDword,  // [ reg + dword ] OR SIB + dword
            0b11 => MODBits::RM,       // direct
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegBits {
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
}

impl RegBits {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            RegBits::EAX => 0b000,
            RegBits::ECX => 0b001,
            RegBits::EDX => 0b010,
            RegBits::EBX => 0b011,
            RegBits::ESP => 0b100,
            RegBits::EBP => 0b101,
            RegBits::ESI => 0b110,
            RegBits::EDI => 0b111,
        }
    }
}

impl From<u8> for RegBits {
    fn from(modrm_byte: u8) -> Self {
        match (modrm_byte & 0b00111000) >> 3 {
            0b000 => RegBits::EAX,
            0b001 => RegBits::ECX,
            0b010 => RegBits::EDX,
            0b011 => RegBits::EBX,
            0b100 => RegBits::ESP,
            0b101 => RegBits::EBP,
            0b110 => RegBits::ESI,
            0b111 => RegBits::EDI,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmBits {
    EAX,
    ECX,
    EDX,
    EBX,
    SIB,
    EBP,
    Disp32,
    ESP,
    ESI,
    EDI,
}

impl From<u8> for RmBits {
    fn from(modrm_byte: u8) -> Self {
        match modrm_byte & 0b00000111 {
            0b000 => RmBits::EAX,
            0b001 => RmBits::ECX,
            0b010 => RmBits::EDX,
            0b011 => RmBits::EBX,
            0b100 => RmBits::ESP,
            0b101 => RmBits::EBP,
            0b110 => RmBits::ESI,
            0b111 => RmBits::EDI,
            _ => unreachable!(),
        }
    }
}

impl RmBits {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            RmBits::EAX => 0b000,
            RmBits::ECX => 0b001,
            RmBits::EDX => 0b010,
            RmBits::EBX => 0b011,
            RmBits::SIB => 0b100,
            RmBits::EBP => 0b101,
            RmBits::Disp32 => 0b101,
            RmBits::ESP => 0b100,
            RmBits::ESI => 0b110,
            RmBits::EDI => 0b111,
        }
    }
}

impl RmBits {
    fn from_mod_bits(md: MODBits, rm: u8) -> Self {
        let rm = rm & 0b00000111;
        match rm {
            0b100 | 0b101 => match md {
                MODBits::RmMemory => {
                    if rm == 0b100 {
                        RmBits::SIB
                    } else {
                        RmBits::Disp32
                    }
                }
                MODBits::RmByte => {
                    if rm == 0b100 {
                        RmBits::SIB
                    } else {
                        RmBits::EBP
                    }
                }
                MODBits::RmDword => {
                    if rm == 0b100 {
                        RmBits::SIB
                    } else {
                        RmBits::EBP
                    }
                }
                MODBits::RM => RmBits::from(rm),
            },
            _ => RmBits::from(rm),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ModRM {
    pub(crate) md: MODBits,
    pub(crate) reg: RegBits,
    pub(crate) rm: RmBits,
}

impl ModRM {
    pub(crate) fn decode(byte: u8) -> Self {
        let md = MODBits::from(byte);
        ModRM {
            md,
            reg: RegBits::from(byte),
            rm: RmBits::from_mod_bits(md, byte),
        }
    }

    pub(crate) fn to_byte_str(self) -> String {
        let mut modrm: u8 = 0b00000000;

        match self.md {
            MODBits::RmMemory => {}
            MODBits::RmByte => modrm |= 0b01000000,
            MODBits::RmDword => modrm |= 0b10000000,
            MODBits::RM => modrm |= 0b11000000,
        }

        match self.reg {
            RegBits::EAX => modrm |= 0b00000000,
            RegBits::ECX => modrm |= 0b00001000,
            RegBits::EDX => modrm |= 0b00010000,
            RegBits::EBX => modrm |= 0b00011000,
            RegBits::ESP => modrm |= 0b00100000,
            RegBits::EBP => modrm |= 0b00101000,
            RegBits::ESI => modrm |= 0b00110000,
            RegBits::EDI => modrm |= 0b00111000,
        }

        modrm |= self.rm.to_byte();

        format!("{:02X}", modrm)
    }
}
