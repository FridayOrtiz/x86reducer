mod disasm;
mod instruction;
mod linear_sweep;
mod recursive_descent;

use crate::instruction::modrm::ModRM;
use crate::instruction::sib::SIB;
use clap::{IntoApp, Parser};
use disasm::Program;
use std::num::ParseIntError;

/// Disassemble a simple binary with x86 instructions.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The x86 binary to open and parse.
    #[clap(short, long)]
    input: Option<String>,
    /// a hex MODRM byte to decode
    #[clap(short, long, parse(try_from_str = parse_hex))]
    modrm: Option<u8>,
    /// a hex SIB byte to decode
    #[clap(short, long, parse(try_from_str = parse_hex))]
    sib: Option<u8>,
}

fn parse_hex(src: &str) -> Result<u8, ParseIntError> {
    u8::from_str_radix(src, 16)
}

fn main() {
    // parse args
    let args = Args::parse();

    if let Some(modrm) = args.modrm {
        println!("Decoding: {:02X}", modrm);
        let modrm = ModRM::decode(modrm);
        println!("{:?}", modrm);
        if let Some(sib) = args.sib {
            println!("Decoding: {:02X}", sib);
            println!("{:?}", SIB::decode(sib, modrm.md));
        }
        return;
    }

    // open the file
    if let Some(file_name) = args.input {
        let mut program = match Program::new(&file_name) {
            Ok(p) => p,
            Err(e) => {
                println!("Error opening file: {:?}", e);
                return;
            }
        };
        if let Ok(()) = program.parse(linear_sweep::linear_sweep) {
            program.print_disassembly();
        }
    } else {
        Args::into_app().print_long_help().unwrap();
    }
}
