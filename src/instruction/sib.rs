use crate::instruction::modrm::MODBits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    None,
    Two,
    Four,
    Eight,
}

impl From<u8> for Scale {
    fn from(sib_byte: u8) -> Self {
        match (sib_byte & 0b11000000) >> 6 {
            0b00 => Scale::None,
            0b01 => Scale::Two,
            0b10 => Scale::Four,
            0b11 => Scale::Eight,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Index {
    EAX,
    ECX,
    EDX,
    EBX,
    None,
    EBP,
    ESI,
    EDI,
}

impl From<u8> for Index {
    fn from(sib_byte: u8) -> Self {
        match (sib_byte & 0b00111000) >> 3 {
            0b000 => Index::EAX,
            0b001 => Index::ECX,
            0b010 => Index::EDX,
            0b011 => Index::EBX,
            0b100 => Index::None,
            0b101 => Index::EBP,
            0b110 => Index::ESI,
            0b111 => Index::EDI,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    Disp32,
    EBP,
    ESI,
    EDI,
}

impl Base {
    fn from_mod_bits(sib_byte: u8, md: MODBits) -> Self {
        match sib_byte & 0b00000111 {
            0b000 => Base::EAX,
            0b001 => Base::ECX,
            0b010 => Base::EDX,
            0b011 => Base::EBX,
            0b100 => Base::ESP,
            0b101 => match md {
                MODBits::RmMemory => Base::Disp32,
                _ => Base::EBP,
            },
            0b110 => Base::ESI,
            0b111 => Base::EDI,
            _ => unreachable!(),
        }
    }
}

/// [scale * index + base]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SIB {
    // Scale is applied to the index
    pub(crate) scale: Scale,
    pub(crate) index: Index,
    pub(crate) base: Base,
}

impl SIB {
    pub(crate) fn to_byte_str(self) -> String {
        let mut sib: u8 = 0b00000000;

        match self.scale {
            Scale::None => {}
            Scale::Two => {
                sib |= 0b01000000;
            }
            Scale::Four => {
                sib |= 0b10000000;
            }
            Scale::Eight => {
                sib |= 0b11000000;
            }
        }

        match self.index {
            Index::EAX => sib |= 0b00000000,
            Index::ECX => sib |= 0b00001000,
            Index::EDX => sib |= 0b00010000,
            Index::EBX => sib |= 0b00011000,
            Index::None => sib |= 0b00100000,
            Index::EBP => sib |= 0b00101000,
            Index::ESI => sib |= 0b00110000,
            Index::EDI => sib |= 0b00111000,
        }

        match self.base {
            Base::EAX => sib |= 0b00000000,
            Base::ECX => sib |= 0b00000001,
            Base::EDX => sib |= 0b00000010,
            Base::EBX => sib |= 0b00000011,
            Base::ESP => sib |= 0b00000100,
            Base::Disp32 => sib |= 0b00000101,
            Base::EBP => sib |= 0b00000101,
            Base::ESI => sib |= 0b00000110,
            Base::EDI => sib |= 0b00000111,
        }

        format!("{:02X}", sib)
    }
}

impl SIB {
    pub(crate) fn decode(byte: u8, md: MODBits) -> Self {
        SIB {
            scale: Scale::from(byte),
            index: Index::from(byte),
            base: Base::from_mod_bits(byte, md),
        }
    }
}
