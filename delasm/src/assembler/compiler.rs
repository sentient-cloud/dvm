use std::collections::{HashMap, HashSet};

use crate::assembler::{
    object::{self, Object, Section, Symbol},
    parser::{self, CompareKind, Token},
};

use delevm::{opcodes::Opcode, vm};

#[derive(Debug, Clone, PartialEq)]
pub enum CompilerError {
    TokenizerError(String),
    UnknownInstruction(String),
    UnknownSyscall(String),
    InvalidOperand(String),
    UnmatchedCompareBracket(String),
    OutOfAddressSpace(String),
    DuplicateSection(String),
    DuplicateLabel(String),
    UnknownLabelAttribute(String),
    NumericLiteralTooLarge(String),
    InvalidNumericLiteral(String),
}

fn mangle_label(current_section: &String, label_parent: &Option<String>, name: &String) -> String {
    let mut new_name = String::new();

    new_name.push_str(current_section);
    new_name.push('$');

    if let Some(parent) = label_parent {
        new_name.push_str(parent);
        new_name.push('.');
    }

    new_name.push_str(name);

    new_name
}

fn assemble_data_entry(
    loc: &parser::Location,
    tokens: &Vec<Token>,
    file_map: &[String],
) -> Result<Vec<u8>, CompilerError> {
    let mut res = vec![];

    for tok in tokens.iter() {
        match tok {
            Token::Literal(loc, kind, literal) => match kind {
                parser::LiteralKind::Binary => {
                    if literal.len() > 64 {
                        return Err(CompilerError::NumericLiteralTooLarge(format!(
                            "[Compilation error] @ {}: Binary literal too large: {}",
                            loc.stringify(file_map),
                            literal
                        )));
                    }

                    let value = u64::from_str_radix(&literal, 2).map_err(|_| {
                        CompilerError::InvalidNumericLiteral(format!(
                            "[Compilation error] @ {}: Invalid binary literal: {}",
                            loc.stringify(&[]),
                            literal
                        ))
                    })?;
                    let value_bytes = value.to_le_bytes();

                    res.extend_from_slice(&value_bytes[..8]);
                }
                parser::LiteralKind::Hex => {
                    if literal.len() > 16 {
                        return Err(CompilerError::NumericLiteralTooLarge(format!(
                            "[Compilation error] @ {}: Hex literal too large: {}",
                            loc.stringify(file_map),
                            literal
                        )));
                    }

                    let value = u64::from_str_radix(&literal, 16).map_err(|_| {
                        CompilerError::InvalidNumericLiteral(format!(
                            "[Compilation error] @ {}: Invalid hex literal: {}",
                            loc.stringify(&[]),
                            literal
                        ))
                    })?;
                    let value_bytes = value.to_le_bytes();
                    res.extend_from_slice(&value_bytes[..8]);
                }
                parser::LiteralKind::Decimal => {
                    let value = literal.parse::<u64>().map_err(|_| {
                        CompilerError::InvalidNumericLiteral(format!(
                            "[Compilation error] @ {}: Invalid decimal literal: {}",
                            loc.stringify(file_map),
                            literal
                        ))
                    })?;
                    let value_bytes = value.to_le_bytes();
                    res.extend_from_slice(&value_bytes[..8]);
                }
                parser::LiteralKind::String => {
                    let mut bytes = parser::unescape_string(literal).as_bytes().to_vec();

                    // pad the string to 8 bytes
                    while bytes.len() % 8 != 0 {
                        bytes.push(0);
                    }

                    res.extend_from_slice(&bytes);
                }
                parser::LiteralKind::Char => {
                    let ch = match parser::unescape_char(&literal) {
                        Some(c) => c,
                        None => {
                            return Err(CompilerError::InvalidNumericLiteral(format!(
                                "[Compilation error] @ {}: Invalid char literal: {}",
                                loc.stringify(file_map),
                                literal
                            )));
                        }
                    };
                    let ch = ch as u64;
                    let value_bytes = ch.to_le_bytes();
                    res.extend_from_slice(&value_bytes[..8]);
                }
            },
            _ => {
                return Err(CompilerError::TokenizerError(format!(
                    "[Compilation error] @ {}: Unexpected token in data entry: {:?}",
                    loc.stringify(file_map),
                    tok
                )));
            }
        }
    }

    assert!(res.len() % 8 == 0);

    Ok(res)
}

fn assemble_immediate(
    loc: &parser::Location,
    kind: parser::LiteralKind,
    literal: &String,
    file_map: &[String],
) -> Result<u16, CompilerError> {
    match kind {
        parser::LiteralKind::Binary => {
            if literal.len() > 16 {
                return Err(CompilerError::NumericLiteralTooLarge(format!(
                    "[Compilation error] @ {}: Binary immediate too large: {}",
                    loc.stringify(file_map),
                    literal
                )));
            }

            u16::from_str_radix(literal, 2).map_err(|_| {
                CompilerError::InvalidNumericLiteral(format!(
                    "[Compilation error] @ {}: Invalid immediate binary literal: {}",
                    loc.stringify(file_map),
                    literal
                ))
            })
        }
        parser::LiteralKind::Hex => {
            if literal.len() > 4 {
                return Err(CompilerError::NumericLiteralTooLarge(format!(
                    "[Compilation error] @ {}: Hex immediate too large: {}",
                    loc.stringify(file_map),
                    literal
                )));
            }

            u16::from_str_radix(literal, 16).map_err(|_| {
                CompilerError::InvalidNumericLiteral(format!(
                    "[Compilation error] @ {}: Invalid immediate hex literal: {}",
                    loc.stringify(file_map),
                    literal
                ))
            })
        }
        parser::LiteralKind::Decimal => literal.parse::<u16>().map_err(|_| {
            CompilerError::InvalidNumericLiteral(format!(
                "[Compilation error] @ {}: Invalid immediate decimal literal: {}",
                loc.stringify(file_map),
                literal
            ))
        }),
        parser::LiteralKind::String => {
            // strings are not valid immediates
            Err(CompilerError::InvalidOperand(format!(
                "[Compilation error] @ {}: String literal cannot be used as an immediate",
                loc.stringify(file_map)
            )))
        }
        parser::LiteralKind::Char => {
            let ch = match parser::unescape_char(&literal) {
                Some(c) => c,
                None => {
                    return Err(CompilerError::InvalidNumericLiteral(format!(
                        "[Compilation error] @ {}: Invalid immediate char literal: {}",
                        loc.stringify(file_map),
                        literal
                    )));
                }
            };

            Ok(ch as u16)
        }
    }
}

fn assemble_register(
    loc: &parser::Location,
    register: Result<vm::Register, usize>,
    file_map: &[String],
) -> Result<u8, CompilerError> {
    match register {
        Ok(reg) => Ok(reg.to_u8()),
        Err(index) => {
            if index < 16 {
                Ok(index as u8)
            } else {
                Err(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: Register index {} is out of bounds (0-15)",
                    loc.stringify(file_map),
                    index
                )))
            }
        }
    }
}

fn assemble_syscall(
    log: &parser::Location,
    syscall: &Result<delevm::Syscall, String>,
    file_map: &[String],
) -> Result<u16, CompilerError> {
    match syscall {
        Ok(syscall) => Ok(syscall.to_u16()),
        Err(name) => Err(CompilerError::UnknownSyscall(format!(
            "[Compilation error] @ {}: Unknown syscall '{}'",
            log.stringify(file_map),
            name
        ))),
    }
}

fn assemble_instruction(
    loc: &parser::Location,
    compare_mode: &CompareKind,
    section_name: &String,
    label_parent: &Option<String>,
    operands: &Vec<Token>,
    file_map: &[String],
) -> Result<(Vec<u8>, Vec<object::Relocation>), Vec<CompilerError>> {
    let mut errors = vec![];

    if operands.len() < 1 {
        errors.push(CompilerError::InvalidOperand(format!(
            "[Compilation error] @ {}: No operands provided for instruction",
            loc.stringify(file_map)
        )));
    }

    // first operand is always opcode
    // (in case of error, default to Nop, which accepts any args)
    let opcode = match &operands[0] {
        Token::Opcode(loc, opcode) => match opcode {
            Ok(opcode) => opcode.clone(),
            Err(str) => {
                errors.push(CompilerError::UnknownInstruction(format!(
                    "[Compilation error] @ {}: Unknown instruction '{}'",
                    loc.stringify(file_map),
                    str
                )));

                Opcode::Nop
            }
        },
        _ => {
            errors.push(CompilerError::InvalidOperand(format!(
                "[Compilation error] @ {}: Expected opcode token, found {:?}",
                loc.stringify(file_map),
                operands[0]
            )));

            Opcode::Nop
        }
    };

    // if there is a 2nd operand and its a compare kind,
    // replace the given compare mode with it
    // this also handles the case where there is no compare
    // mode, and no extra operands
    let (compare_mode, operands) = match operands.get(1) {
        Some(Token::Compare(_, kind)) => (kind.clone(), &operands[2..]),
        _ => (compare_mode.clone(), &operands[1..]),
    };

    let a = opcode.to_u8()
        | match compare_mode {
            CompareKind::None => 0b0000_0000,
            CompareKind::True => 0b0100_0000,
            CompareKind::False => 0b1000_0000,
            CompareKind::Maybe => 0b1100_0000,
        };

    let mut b = 0u8;
    let mut c = 0u8;
    let mut d = 0u16;

    let mut relocations = vec![];

    match opcode {
        // Nop, ignore any operands
        Opcode::Nop => {}

        // JumpImm and CallImm, both except a label or immediate operand
        Opcode::JumpImm | Opcode::CallImm => {
            if operands.len() != 1 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 1 operand, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            }

            match &operands[0] {
                Token::Label(_, (name, _)) => {
                    relocations.push(object::Relocation {
                        kind: object::RelocationKind::Absolute,
                        from_section: section_name.clone(),
                        to_section: section_name.clone(),
                        to_symbol: mangle_label(section_name, label_parent, name),
                        offset: 2,
                        addend: 0,
                    });

                    b = 0;
                    c = 0;
                    d = 0;
                }
                Token::Immediate(_, (kind, value)) => {
                    match assemble_immediate(loc, kind.clone(), value, file_map) {
                        Ok(imm) => {
                            b = 0;
                            c = 0;
                            d = imm as u16;
                        }
                        Err(err) => {
                            errors.push(err);
                        }
                    }
                }
                _ => {
                    errors.push(CompilerError::InvalidOperand(format!(
                        "[Compilation error] @ {}: {} expects a label or immediate operand, found {:?}",
                        loc.stringify(file_map),
                        opcode.to_str(),
                        operands[0].to_str(),
                    )));
                }
            }
        }

        // CallPtr, expects a register
        Opcode::CallPtr => {
            if operands.len() != 1 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 1 operand, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match &operands[0] {
                    Token::Register(_, reg) => {
                        b = 0;
                        c = match assemble_register(loc, reg.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        d = 0;
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects a register operand, found {:?}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                        )));
                    }
                }
            }
        }

        // Ret, no operands
        Opcode::Return => {
            if operands.len() != 0 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects no operands, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            }
            b = 0;
            c = 0;
            d = 0;
        }

        // Abort, expects an immediate operand
        Opcode::Abort => {
            if operands.len() != 1 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 1 operand, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match &operands[0] {
                    Token::Immediate(_, (kind, value)) => {
                        match assemble_immediate(loc, kind.clone(), value, file_map) {
                            Ok(imm) => {
                                b = 0;
                                c = 0;
                                d = imm as u16;
                            }
                            Err(err) => {
                                errors.push(err);
                            }
                        }
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects an immediate operand, found {}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                        )));
                    }
                }
            }
        }

        // Load, USet, UAdd, USub, expects a register and an immediate or label or data addr label
        Opcode::Load | Opcode::USet | Opcode::UAdd | Opcode::USub => {
            if operands.len() != 2 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 2 operands, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match (&operands[0], &operands[1]) {
                    (Token::Register(_, reg_a), Token::Immediate(_, (kind, value))) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = 0;
                        match assemble_immediate(loc, kind.clone(), value, file_map) {
                            Ok(imm) => d = imm as u16,
                            Err(err) => {
                                errors.push(err);
                                d = 0; // default to 0 if error
                            }
                        };
                    }
                    (Token::Register(_, reg_a), Token::Label(_, (name, _))) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = 0;
                        relocations.push(object::Relocation {
                            kind: object::RelocationKind::Absolute,
                            from_section: section_name.clone(),
                            to_section: section_name.clone(),
                            to_symbol: mangle_label(section_name, label_parent, name),
                            offset: 2,
                            addend: 0,
                        });
                    }
                    (Token::Register(_, reg_a), Token::DataAddrLabel(_, (section, name))) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = 0;
                        relocations.push(object::Relocation {
                            kind: object::RelocationKind::Absolute,
                            from_section: section_name.clone(),
                            to_section: section.clone(),
                            to_symbol: mangle_label(section, &None, name),
                            offset: 2,
                            addend: 0,
                        });
                    }
                    _ => {
                        #[rustfmt::skip]
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects a register and an immediate or label or data label operand, found {} and {}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                            operands[1].to_str(),
                        )));
                    }
                }
            }
        }

        // Push and Pop, expects a register
        Opcode::Push | Opcode::Pop => {
            if operands.len() != 1 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 1 operand, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match &operands[0] {
                    Token::Register(_, reg) => {
                        b = match assemble_register(loc, reg.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = 0;
                        d = 0;
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects a register operand, found {}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                        )));
                    }
                }
            }
        }

        // Move, Peek, StorePtr, LoadPtr, Not, CvtI2F, CvtF2I
        // expects two registers
        Opcode::Move
        | Opcode::Peek
        | Opcode::StorePtr
        | Opcode::LoadPtr
        | Opcode::Not
        | Opcode::CvtI2F
        | Opcode::CvtF2I => {
            if operands.len() != 2 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 2 operands, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match (&operands[0], &operands[1]) {
                    (Token::Register(_, reg_a), Token::Register(_, reg_b)) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = match assemble_register(loc, reg_b.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        d = 0;
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                        "[Compilation error] @ {}: {} expects two register operands, found {} and {}",
                        loc.stringify(file_map),
                        opcode.to_str(),
                        operands[0].to_str(),
                        operands[1].to_str(),
                    )));
                    }
                }
            }
        }

        // And, Or, Xor, ShiftL, ShiftR, IAdd, ISub, IMul, IDiv, IRem, FAdd, FSub, FMul, FDiv, FRem
        // expects three registers
        Opcode::And
        | Opcode::Or
        | Opcode::Xor
        | Opcode::ShiftL
        | Opcode::ShiftR
        | Opcode::IAdd
        | Opcode::ISub
        | Opcode::IMul
        | Opcode::IDiv
        | Opcode::IRem
        | Opcode::FAdd
        | Opcode::FSub
        | Opcode::FMul
        | Opcode::FDiv
        | Opcode::FRem => {
            if operands.len() != 3 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 3 operands, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match (&operands[0], &operands[1], &operands[2]) {
                    (
                        Token::Register(_, reg_a),
                        Token::Register(_, reg_b),
                        Token::Register(_, reg_c),
                    ) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = match assemble_register(loc, reg_b.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        d = match assemble_register(loc, reg_c.clone(), file_map) {
                            Ok(reg) => reg as u16,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                        "[Compilation error] @ {}: {} expects three register operands, found {:?}, {:?} and {:?}",
                        loc.stringify(file_map),
                        opcode.to_str(),
                        operands[0],
                        operands[1],
                        operands[2]
                    )));
                    }
                }
            }
        }

        // ILess, IEqual, IGreater, FLess, FEqual, FGreater expects two registers (2nd reg placed in d)
        Opcode::ILess
        | Opcode::IEqual
        | Opcode::IGreater
        | Opcode::FLess
        | Opcode::FEqual
        | Opcode::FGreater => {
            if operands.len() != 2 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 2 operands, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match (&operands[0], &operands[1]) {
                    (Token::Register(_, reg_a), Token::Register(_, reg_b)) => {
                        c = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        d = match assemble_register(loc, reg_b.clone(), file_map) {
                            Ok(reg) => reg as u16,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects two register operands, found {} and {}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                            operands[1].to_str(),
                        )));
                    }
                }
            }
        }

        // FEpsilon, expects a single register placed in c
        Opcode::FEpsilon => {
            if operands.len() != 1 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 1 operand, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match &operands[0] {
                    Token::Register(_, reg) => {
                        b = 0;
                        c = match assemble_register(loc, reg.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        d = 0;
                    }
                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects a register operand, found {}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                        )));
                    }
                }
            }
        }

        // Syscall, expects two registers and a syscall identifier or immediate
        Opcode::Syscall => {
            if operands.len() != 3 {
                errors.push(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: {} expects 3 operands, found {}",
                    loc.stringify(file_map),
                    opcode.to_str(),
                    operands.len()
                )));
            } else {
                match (&operands[0], &operands[1], &operands[2]) {
                    (
                        Token::Register(_, reg_a),
                        Token::Register(_, reg_b),
                        Token::Immediate(_, (kind, value)),
                    ) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = match assemble_register(loc, reg_b.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        match assemble_immediate(loc, kind.clone(), value, file_map) {
                            Ok(imm) => d = imm as u16,
                            Err(err) => {
                                errors.push(err);
                                d = 0; // default to 0 if error
                            }
                        };
                    }
                    (
                        Token::Register(_, reg_a),
                        Token::Register(_, reg_b),
                        Token::Syscall(_, syscall),
                    ) => {
                        b = match assemble_register(loc, reg_a.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        c = match assemble_register(loc, reg_b.clone(), file_map) {
                            Ok(reg) => reg,
                            Err(err) => {
                                errors.push(err);
                                0 // default to 0 if error
                            }
                        };
                        match assemble_syscall(loc, &syscall, file_map) {
                            Ok(syscall_id) => d = syscall_id,
                            Err(err) => {
                                errors.push(err);
                                d = 0; // default to 0 if error
                            }
                        };
                    }

                    _ => {
                        errors.push(CompilerError::InvalidOperand(format!(
                            "[Compilation error] @ {}: {} expects two registers and a syscall identifier or immediate, found {}, {} and {}",
                            loc.stringify(file_map),
                            opcode.to_str(),
                            operands[0].to_str(),
                            operands[1].to_str(),
                            operands[2].to_str(),
                        )));
                    }
                }
            }
        }
    }

    if errors.len() > 0 {
        return Err(errors);
    }

    assert!(b < 16, "expected b to only use lower 4 bits, got {}", b);
    assert!(c < 16, "expected c to only use lower 4 bits, got {}", c);

    // encode instruction as:
    // 0: a[2 compare bits + 6 bit opcode]
    // 1: lower 4 bits of b placed in the upper 4 bits,
    //    lower 4 bits of c placed in the lower 4 bits
    // 2: upper 8 bits of d
    // 3: lower 8 bits of d
    Ok((
        vec![
            a,
            (b << 4) | (c & 0xF),
            ((d >> 8) & 0xFF) as u8,
            (d & 0xFF) as u8,
        ],
        relocations,
    ))
}

pub fn compile_tokens(
    tokens: &Vec<Token>,
    file_map: &[String],
) -> Result<Object, Vec<CompilerError>> {
    // sections: (section name, section)
    let mut sections: HashMap<String, Section> = HashMap::new();
    let mut symbols = vec![];
    let mut relocations = vec![];

    // compare kind stack: (CompareKind, (source line, source column))
    let mut compare_kind_stack = vec![(CompareKind::None, (0, 0))];
    let mut current_section: Option<String> = None;
    let mut current_offset: usize = 0;

    let mut current_label_parent: Option<String> = None;
    let mut labels: HashSet<String> = HashSet::new();

    let mut errors = vec![];

    let mut tokens = tokens.iter().peekable();

    while tokens.peek().is_some() {
        let next = tokens.next().unwrap();

        match next {
            Token::Error(loc, error) => errors.push(CompilerError::TokenizerError(format!(
                "[Compilation error] @ {}: {}",
                loc.stringify(file_map),
                error.err_str()
            ))),
            Token::Comment(..) => continue,
            Token::Include(..) => continue,
            Token::SectionAddr(loc, addr) => {
                if let Some(ref current_section) = current_section {
                    let section = sections.get_mut(current_section).unwrap();

                    if *addr > 0xFFFF {
                        errors.push(CompilerError::OutOfAddressSpace(format!(
                            "[Compilation error] @ {}: Section address {} is out of address space",
                            loc.stringify(file_map),
                            addr
                        )));
                    } else {
                        // set the section address, and push data into section up to the offset
                        current_offset = *addr
                            * match section.kind {
                                object::SectionKind::Code => 4, // code section entries are 4 bytes
                                object::SectionKind::Data => 8, // data section entries are 8 bytes
                            };

                        while current_offset > section.data.len() {
                            section.data.push(0);
                        }
                    }
                } else {
                    errors.push(CompilerError::OutOfAddressSpace(format!(
                        "[Compilation error] @ {}: Unexpected section address, must be inside a section",
                        loc.stringify(file_map)
                    )));
                }
            }
            Token::Section(loc, (name, pinned_addr, kind)) => {
                let original_name = name;

                // if its unnamed, imply the name based on the section kind
                let name = match name {
                    Some(name) => name.clone(),
                    None => match kind {
                        parser::SectionKind::Code => "code".to_string(),
                        parser::SectionKind::Data => "data".to_string(),
                    },
                };

                // check the pinned addr if there is one
                if let Some(addr) = *pinned_addr {
                    if addr > 0xFFFF {
                        errors.push(CompilerError::OutOfAddressSpace(format!(
                            "[Compilation error] @ {}: Pinned section addr {} is out of address space",
                            loc.stringify(file_map),
                            addr
                        )));
                    }
                }

                if sections.contains_key(&name) {
                    // (we could just switch to a different section,
                    //  but that complicates label logic, so lets just error)
                    errors.push(CompilerError::DuplicateLabel(format!(
                        "[Compilation error] @ {}: Section '{}' already exists",
                        loc.stringify(file_map),
                        name
                    )));
                } else {
                    // create a new section
                    let section = Section {
                        name: Some(name.clone()),
                        kind: match kind {
                            &parser::SectionKind::Code => object::SectionKind::Code,
                            &parser::SectionKind::Data => object::SectionKind::Data,
                        },
                        // set the pinned addr, or default to 0xFFFF (assigned by linker)
                        address: pinned_addr.unwrap_or(0xFFFF) as u16,
                        data: vec![],
                    };

                    sections.insert(name.clone(), section);
                    current_section = Some(name.clone());

                    // reset offset
                    current_offset = 0;

                    // reset label parent
                    current_label_parent = None;

                    // reset compare kind stack
                    if compare_kind_stack.len() != 1 {
                        let (_, last_cmp) = compare_kind_stack.last().unwrap();
                        errors.push(CompilerError::UnmatchedCompareBracket(format!(
                            "[Compilation error] @ {}: Section '{}' opened with unmatched compare bracket {}",
                            loc.stringify(file_map), name,
                            format!("(last compare block opened at {}:{})",
                                    last_cmp.0,
                                    last_cmp.1
                                )
                        )));
                    }

                    compare_kind_stack = vec![(CompareKind::None, (0, 0))];

                    // generate an unnamed symbol that refers to the start of the section,
                    // and if it has an explicit name, make its linkage export
                    let has_export_linkage = original_name.is_some();

                    let symbol = Symbol {
                        name: None,
                        linkage: if has_export_linkage {
                            object::SymbolLinkage::Export
                        } else {
                            object::SymbolLinkage::Internal
                        },
                        kind: match kind {
                            &parser::SectionKind::Code => object::SymbolKind::Code,
                            &parser::SectionKind::Data => object::SymbolKind::Data,
                        },
                        offset: 0,
                        section_name: Some(name.clone()),
                    };

                    symbols.push(symbol);
                }
            }
            Token::Label(loc, (name, attribs)) => {
                for attrib in attribs.iter() {
                    match attrib {
                        Ok(_) => {}
                        Err(err) => errors.push(CompilerError::UnknownLabelAttribute(format!(
                            "[Compilation error] @ {}: Unknown label attribute '{}'",
                            loc.stringify(file_map),
                            err
                        ))),
                    }
                }

                if let Some(ref current_section) = current_section {
                    let section = sections.get_mut(current_section).unwrap();

                    let has_export_linkage = attribs.contains(&Ok(parser::LabelAttribute::Export));

                    let label_name = if has_export_linkage {
                        // if the label is exported, use the name as is
                        name.clone()
                    } else {
                        // else prefix with the section name and parent label if any
                        // (section$parent.label)
                        mangle_label(current_section, &current_label_parent, name)
                    };

                    // check if the label already exists
                    if labels.contains(&label_name) {
                        errors.push(CompilerError::DuplicateLabel(format!(
                            "[Compilation error] @ {}: Label '{}' already defined",
                            loc.stringify(file_map),
                            label_name
                        )));
                    } else {
                        // create a new symbol for the label

                        let symbol = Symbol {
                            name: Some(label_name.clone()),
                            linkage: if has_export_linkage {
                                object::SymbolLinkage::Export
                            } else {
                                object::SymbolLinkage::Internal
                            },
                            kind: match section.kind {
                                object::SectionKind::Code => object::SymbolKind::Code,
                                object::SectionKind::Data => object::SymbolKind::Data,
                            },
                            offset: (section.data.len() / 4) as u64, // offset in 32-bit words
                            section_name: Some(current_section.clone()),
                        };

                        labels.insert(label_name.clone());

                        symbols.push(symbol);
                    }

                    // if the label is a parent label, set the current label parent
                    if attribs.contains(&Ok(parser::LabelAttribute::LabelParent)) {
                        current_label_parent = Some(name.clone());
                    }
                } else {
                    errors.push(CompilerError::DuplicateLabel(format!(
                        "[Compilation error] @ {}: Label '{}' defined outside of any section",
                        loc.stringify(file_map),
                        name
                    )));
                }
            }
            Token::CompareBlockBegin(loc, kind) => {
                // check so that we are inside a code section
                if let Some(ref current_section) = current_section {
                    let section = sections.get(current_section).unwrap();

                    if !section.kind.is_code() {
                        errors.push(CompilerError::UnmatchedCompareBracket(format!(
                            "[Compilation error] @ {}: Compare block opened in non-code section '{}'",
                            loc.stringify(file_map),
                            current_section
                        )));
                    }
                } else {
                    errors.push(CompilerError::UnmatchedCompareBracket(format!(
                        "[Compilation error] @ {}: Compare block opened outside of any section",
                        loc.stringify(file_map)
                    )));
                }

                compare_kind_stack.push((*kind, (loc.line, loc.column)));
            }
            Token::CompareBlockEnd(loc) => {
                // check so that we are inside a code section
                if let Some(ref current_section) = current_section {
                    let section = sections.get(current_section).unwrap();

                    if !section.kind.is_code() {
                        errors.push(CompilerError::UnmatchedCompareBracket(format!(
                            "[Compilation error] @ {}: Compare block closed in non-code section '{}'",
                            loc.stringify(file_map),
                            current_section
                        )));
                    }
                } else {
                    errors.push(CompilerError::UnmatchedCompareBracket(format!(
                        "[Compilation error] @ {}: Compare block closed outside of any section",
                        loc.stringify(file_map)
                    )));
                }

                // pop the last compare kind
                if compare_kind_stack.len() > 1 {
                    compare_kind_stack.pop();
                } else {
                    errors.push(CompilerError::UnmatchedCompareBracket(format!(
                        "[Compilation error] @ {}: Unmatched compare block end, no open compare block",
                        loc.stringify(file_map)
                    )));
                }
            }
            Token::DataEntry(loc, data_tokens) => {
                if let Some(ref section) = current_section {
                    let section = sections.get_mut(section).unwrap();

                    match assemble_data_entry(loc, data_tokens, file_map) {
                        Ok(assembled) => {
                            section.data.extend(assembled);
                        }
                        Err(err) => {
                            errors.push(err);
                        }
                    }
                } else {
                    errors.push(CompilerError::OutOfAddressSpace(format!(
                        "[Compilation error] @ {}: Data entry outside of any section",
                        loc.stringify(file_map)
                    )));
                }
            }
            Token::Instruction(loc, operands) => {
                if let Some(ref section) = current_section {
                    let section = sections.get_mut(section).unwrap();

                    match assemble_instruction(
                        loc,
                        &compare_kind_stack.last().unwrap().0,
                        &current_section.as_ref().unwrap(),
                        &current_label_parent,
                        operands,
                        file_map,
                    ) {
                        Ok((assembled, relocs)) => {
                            // push the relocations, setting their section, and updating the offset
                            // (offset is currently relative to the instruction)
                            relocations.extend(relocs.iter().map(|reloc| object::Relocation {
                                from_section: reloc.from_section.clone(),
                                to_section: reloc.to_section.clone(),
                                to_symbol: reloc.to_symbol.clone(),
                                kind: reloc.kind.clone(),
                                offset: current_offset as u64 + reloc.offset as u64,
                                addend: reloc.addend,
                            }));

                            current_offset += assembled.len();
                            section.data.extend(assembled);
                        }
                        Err(errs) => {
                            errors.extend(errs);
                        }
                    }
                } else {
                    errors.push(CompilerError::InvalidOperand(format!(
                        "[Compilation error] @ {}: Instruction outside of any section",
                        loc.stringify(file_map)
                    )));
                }
            }

            _ => todo!(),
        }
    }

    if errors.len() > 0 {
        return Err(errors);
    }

    let mut obj = Object::new();
    obj.sections = sections.values().cloned().collect();
    obj.symbols = symbols;
    obj.relocations = relocations;
    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_compile_1() {
        let src = r#"
; this is a comment   
$code
.main(export):
        load R0, data[.D0] ; load 1 from $data
        load R4, data[.D1] ; load 1000 from $data

.L0:    and R3, R0, R1                ; R3 = R0 & R1
        iequ R2, R3                   ; if R1 was even
        @t [
            push R0                   ; save R0
            syscall R0, R1, print_i64 ; print even number
            pop R0                    ; restore R0
        ]
        iadd R1, R0, R1               ; add 1 to R1
        iequ R1, R4                   ; if R1 == 1000
        @t [
            uset R1, meow[.D0]            ; set R1 to addr of the string
            syscall R0, R1, print_string  ; print it
            call .lib_function            ; call a library function
            abort #0x0000
        ]
        jump .L0

$code(library)
.lib_function(export):
    ret

$data
.D0:    0b01 ; increment size
.D1:    1000 ; iteration limit
@0x0004

; a section named meow, at pinned addr 0x1000
$data(meow) @ 0x1000
.D0:    "meowmeowmeow\x21\0"
@0x0004 0xfacefeeddeadbeef
"#;
        let (tokens, file_map) = parser::tokenize("file".to_string(), &src.to_string());

        println!("{}", src);

        println!("{}", parser::stringify_tokens(&tokens, &file_map));

        let result = compile_tokens(&tokens, &file_map);

        match result {
            Ok(object) => {
                println!("Compilation success");
                println!("{:#?}", object);
            }
            Err(errors) => {
                println!("Compilation errors:");
                println!("{:#?}", errors);
            }
        }
    }
}
