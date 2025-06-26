use delevm::{opcodes::Opcode, vm::CompareFlag};

use crate::instruction::{Instruction, format_immediate, format_register};

#[derive(Debug)]
struct DecodedInsn {
    insn: Instruction,
    offset: usize,
    label: Option<usize>, // if this instruction is a jump target, it will have a label
    jmp_target: Option<usize>, // an immediate addr to jump to
    data_ref: Option<usize>, // an immediate addr to the data section
}

#[derive(Debug)]
struct UnknownInsn {
    raw: u32,
    offset: usize,
    label: Option<usize>, // uknowns can still have a label, if its jumped to
}

#[derive(Debug)]
enum Insn {
    Decoded(DecodedInsn),
    Unknown(UnknownInsn),
}

impl Insn {
    fn cmpflag(&self) -> CompareFlag {
        match self {
            Insn::Decoded(decoded) => decoded.insn.compare,
            Insn::Unknown(_) => CompareFlag::None, // Unknown instructions don't have a compare flag
        }
    }

    fn offset(&self) -> usize {
        match self {
            Insn::Decoded(decoded) => decoded.offset,
            Insn::Unknown(unknown) => unknown.offset,
        }
    }

    fn label(&self) -> Option<usize> {
        match self {
            Insn::Decoded(decoded) => decoded.label,
            Insn::Unknown(unknown) => unknown.label,
        }
    }

    fn set_label(&mut self, label: usize) {
        match self {
            Insn::Decoded(decoded) => decoded.label = Some(label),
            Insn::Unknown(unknown) => unknown.label = Some(label),
        }
    }

    fn jmp_target(&self) -> Option<usize> {
        match self {
            Insn::Decoded(decoded) => decoded.jmp_target,
            Insn::Unknown(_) => None,
        }
    }

    fn data_ref(&self) -> Option<usize> {
        match self {
            Insn::Decoded(decoded) => decoded.data_ref,
            Insn::Unknown(_) => None,
        }
    }
}

pub fn disassemble(code: &[u32], data: &[u64]) -> String {
    // disassemble each instruction, also pick out the jump targets
    let mut disasm = code
        .iter()
        .enumerate()
        .map(|(i, &insn)| {
            let decoded = Instruction::decode(insn.to_be_bytes());

            if let Some(decoded) = decoded {
                let jmp_target = match decoded.opcode {
                    Opcode::JumpImm | Opcode::CallImm => Some(decoded.c as usize),
                    _ => None,
                };

                let data_ref = match decoded.opcode {
                    Opcode::Load => Some(decoded.c as usize),
                    _ => None,
                };

                Insn::Decoded(DecodedInsn {
                    insn: decoded,
                    offset: i,
                    label: None,
                    jmp_target,
                    data_ref,
                })
            } else {
                Insn::Unknown(UnknownInsn {
                    raw: insn,
                    offset: i,
                    label: None,
                })
            }
        })
        .collect::<Vec<_>>();

    // assign labels to the instructions references by jump targets
    let mut label = 0;
    let mut label_names = vec![];

    // labels for data section, map of (index, label name)
    let mut data_labels = std::collections::HashMap::new();

    for i in 0..disasm.len() {
        if let Some(jmp_target) = disasm[i].jmp_target() {
            // facked up jump
            if jmp_target >= disasm.len() {
                continue;
            }

            // if the jump target is already labeled, skip it
            if disasm[jmp_target].label().is_some() {
                continue;
            }

            // assign a label to the jump target
            disasm[jmp_target].set_label(label);
            label_names.push(format!("L{}", label));
            label += 1;
        }

        // if there is a data_ref in this instruction, add a label if it doesn't exist
        if let Some(data_ref) = disasm[i].data_ref() {
            if !data_labels.contains_key(&data_ref) {
                data_labels.insert(data_ref, format!("D{}", data_labels.len()));
            }
        }
    }

    // put together the disassembled code
    let mut code_section = "$code\n".to_string();

    const BATCH_CMP_THRESHOLD: usize = 3;
    let mut num_consecutive_cmps = 0;

    for i in 0..disasm.len() {
        let insn = &disasm[i];

        // print label, is there is one
        if let Some(label) = insn.label() {
            code_section.push_str(&format!(".{}:\n", label_names[label]));
        }

        // if the compare flag isnt none, check how many instructions forward have the same
        if !matches!(insn.cmpflag(), CompareFlag::None) && num_consecutive_cmps == 0 {
            let curr = insn.cmpflag();

            for j in i + 1..disasm.len() {
                if disasm[j].cmpflag() == curr {
                    num_consecutive_cmps += 1;
                } else {
                    break;
                }
            }

            if num_consecutive_cmps < BATCH_CMP_THRESHOLD - 1 {
                num_consecutive_cmps = 0;
            } else {
                num_consecutive_cmps += 2; // yes

                match curr {
                    CompareFlag::None => unreachable!(),
                    CompareFlag::True => code_section.push_str("        @t [\n"),
                    CompareFlag::False => code_section.push_str("        @f [\n"),
                    CompareFlag::Maybe => code_section.push_str("        @e [\n"),
                }
            }
        }

        let cmp_was_omitted = num_consecutive_cmps > 0;

        if cmp_was_omitted {
            num_consecutive_cmps -= 1;

            if num_consecutive_cmps == 0 {
                code_section.push_str("        ]\n");
            }
        }

        // if its the first one, or there is a label, print the offset
        if i == 0 || insn.label().is_some() {
            code_section.push_str(&format!("0x{:04x}  ", insn.offset()));
        } else {
            code_section.push_str("        ");
        }

        // disassemble the instruction, with fallback for unknowns
        let mut code = match &insn {
            Insn::Decoded(decoded) => decoded.insn.disassemble_impl(
                insn.jmp_target().is_some(),
                // omit immediate addr for loads
                matches!(decoded.insn.opcode, Opcode::Load),
                // omit addr register for load/store ptr
                matches!(decoded.insn.opcode, Opcode::LoadPtr | Opcode::StorePtr),
            ),
            Insn::Unknown(unknown) => format!("0x{:08x}", unknown.raw),
        };

        if cmp_was_omitted && code.starts_with('@') {
            code = "    ".to_string() + &code[3..]
        }

        // handle placeholders
        match &insn {
            // jump target, replace with label name if available
            Insn::Decoded(decoded) if decoded.jmp_target.is_some() => {
                let jmp_target = decoded.jmp_target.unwrap();

                // if its out of bounds, or the label doesnt exist, just print the target in hex
                if disasm.len() <= jmp_target
                    || label_names.len() <= disasm[jmp_target].label().unwrap()
                {
                    code = code.replace("%JUMP_TARGET%", &format_immediate(jmp_target as u16));
                } else {
                    let label_name = &label_names[disasm[jmp_target].label().unwrap()];
                    code = code.replace("%JUMP_TARGET%", &format!(".{}", label_name));
                }
            }
            // immediate address into data section
            Insn::Decoded(decoded) if matches!(decoded.insn.opcode, Opcode::Load) => {
                code = code.replace(
                    "%DATA_ADDR_IMM%",
                    // if the data section has a label for this address, use it
                    &if data_labels.contains_key(&(decoded.insn.c as usize)) {
                        format!(
                            "data[.{}]",
                            data_labels.get(&(decoded.insn.c as usize)).unwrap()
                        )
                    } else {
                        format!("data[{}]", format_immediate(decoded.insn.c))
                    },
                );
            }
            // dst as register addr into data section
            Insn::Decoded(decoded) if matches!(decoded.insn.opcode, Opcode::StorePtr) => {
                code = code.replace(
                    "%DATA_ADDR_REG%",
                    &format!("data[{}]", format_register(decoded.insn.a)),
                );
            }
            // src as register addr into data section
            Insn::Decoded(decoded) if matches!(decoded.insn.opcode, Opcode::LoadPtr) => {
                code = code.replace(
                    "%DATA_ADDR_REG%",
                    &format!("data[{}]", format_register(decoded.insn.b)),
                );
            }
            _ => {}
        }

        code_section.push_str(&code);

        if i < disasm.len() - 1 {
            code_section.push('\n');
        }
    }

    // put together the data section
    let mut data_section = "$data\n".to_string();

    for (i, &value) in data.iter().enumerate() {
        // if the value is nonzero, or has a label, write it out
        if value != 0 || data_labels.contains_key(&i) {
            if let Some(label) = data_labels.get(&i) {
                data_section.push_str(&format!(".{}:\n", label));
            }

            data_section.push_str(&format!("0x{:04x}  ", i));
            data_section.push_str(&format!("0x{:016x}", value));

            if i < data.len() - 1 {
                data_section.push('\n');
            }
        }
    }

    // what a disasmer

    code_section + "\n\n" + &data_section
}

#[cfg(test)]
mod tests {
    use delevm::{
        syscall::Syscall,
        vm::{CompareFlag, Register},
    };

    use super::*;

    #[test]
    fn test_disassemble_code_section() {
        let code = [
            // load data addr 0 into r0 (it's 1)
            Instruction::new().with_load(Register::R0, 0),
            // AND r1 with 1
            Instruction::new().with_and(Register::R3, Register::R0, Register::R1),
            // check if its 0 (r2 is reset to 0 and not touched)
            Instruction::new().with_i_equal(Register::R2, Register::R3),
            // next syscall will clobber r0 (we could obviously just use a different
            // dst register, but thats boring), so save r0 to stack
            Instruction::new()
                .with_compare(CompareFlag::True)
                .with_push(Register::R0),
            // print if the check was true (r1 is even)
            Instruction::new()
                .with_compare(CompareFlag::True)
                .with_syscall(Register::R0, Register::R1, Syscall::PrintI64),
            // restore r0 from stack
            Instruction::new()
                .with_compare(CompareFlag::True)
                .with_pop(Register::R0),
            // r1 = r0 + r1
            Instruction::new().with_i_add(Register::R1, Register::R0, Register::R1),
            // jmp 1
            Instruction::new().with_jump_imm(1),
        ]
        .iter()
        .map(|insn| u32::from_be_bytes(insn.encode()))
        .collect::<Vec<_>>();

        let mut data = [0u64; 65536];

        data[0] = 1;
        data[124] = 2;

        println!("{}", disassemble(&code, &data));
    }
}
