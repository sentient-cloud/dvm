use std::collections::{HashMap, HashSet};

use crate::assembler::{
    object::{self, Object, Section, Symbol},
    parser::{self, CompareKind, Token},
};

use delevm::opcodes::Opcode;

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
                    let mut bytes = literal.as_bytes().to_vec();

                    // pad the string to 8 bytes
                    while bytes.len() % 8 != 0 {
                        bytes.push(0);
                    }

                    res.extend_from_slice(&bytes);
                }
                parser::LiteralKind::Char => {
                    let ch = match literal.chars().next() {
                        Some(c) => c,
                        None => {
                            return Err(CompilerError::NumericLiteralTooLarge(format!(
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

fn assemble_instruction(
    loc: &parser::Location,
    compare_mode: &CompareKind,
    operands: &Vec<Token>,
    file_map: &[String],
) -> Result<(Vec<u8>, Vec<object::Relocation>), CompilerError> {
    if operands.len() < 1 {
        return Err(CompilerError::InvalidOperand(format!(
            "[Compilation error] @ {}: No operands provided for instruction",
            loc.stringify(file_map)
        )));
    }

    // first operand is always opcode
    let opcode = match &operands[0] {
        Token::Opcode(loc, opcode) => match opcode {
            Ok(opcode) => opcode.clone(),
            Err(str) => {
                return Err(CompilerError::UnknownInstruction(format!(
                    "[Compilation error] @ {}: Unknown instruction '{}'",
                    loc.stringify(file_map),
                    str
                )));
            }
        },
        _ => {
            return Err(CompilerError::InvalidOperand(format!(
                "[Compilation error] @ {}: Expected opcode, found {:?}",
                loc.stringify(file_map),
                operands[0]
            )));
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
    let mut c = 0u16;

    let mut relocations = vec![];

    match opcode {
        Opcode::Nop => {
            if operands.len() != 0 {
                return Err(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: Nop expects no operands, found {}",
                    loc.stringify(file_map),
                    operands.len()
                )));
            }

            b = 0;
            c = 0;
        }
        Opcode::JumpImm => {
            if operands.len() != 1 {
                return Err(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: JumpImm expects 1 operand, found {}",
                    loc.stringify(file_map),
                    operands.len()
                )));
            }
        }
        Opcode::CallImm => {
            if operands.len() != 1 {
                return Err(CompilerError::InvalidOperand(format!(
                    "[Compilation error] @ {}: CallImm expects 1 operand, found {}",
                    loc.stringify(file_map),
                    operands.len()
                )));
            }
        }
        _ => println!(
            "Unimplemented assemble: opcode {:?} with compare mode {:?}",
            opcode, compare_mode
        ),
    }

    Ok((vec![a, b, (c >> 8) as u8, (c & 0xFF) as u8], relocations))
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
                        let mut new_name = String::new();

                        new_name.push_str(current_section);
                        new_name.push('$');

                        if let Some(ref parent) = current_label_parent {
                            new_name.push_str(parent);
                            new_name.push('.');
                        }

                        new_name.push_str(name);

                        new_name
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
                        operands,
                        file_map,
                    ) {
                        Ok((assembled, relocs)) => {
                            relocations.extend(relocs);

                            current_offset += assembled.len();
                            section.data.extend(assembled);
                        }
                        Err(err) => {
                            errors.push(err);
                        }
                    }
                } else {
                    errors.push(CompilerError::InvalidOperand(format!(
                        "[Compilation error] @ {}: Instruction outside of any section",
                        loc.stringify(file_map)
                    )));
                }
            }

            _ => {}
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
        iequ R3, R1, R4               ; if R1 == 1000
        @t [
            syscall R0, meow[.D0], print_string
            call .lib_function
            abort #0x0000
        ]
        jump .L0

$code(library)
.lib_function(export):
    @t [
        "abcdef"
        @f ret
    ]
    

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

        println!("{:?}", file_map);
        println!("{}", parser::stringify_tokens(&tokens, &file_map));

        let result = compile_tokens(&tokens, &file_map);

        match result {
            Ok(object) => {
                println!("{:#?}", object);
            }
            Err(errors) => {
                println!("Compilation errors:");
                println!("{:#?}", errors);
            }
        }
    }
}
