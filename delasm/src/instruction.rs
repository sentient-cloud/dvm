use delevm::{
    opcodes::Opcode,
    syscall::Syscall,
    vm::{CompareFlag, Register},
};

pub fn format_immediate(value: u16) -> String {
    if value < 256 {
        format!("#{}", value)
    } else {
        format!("#0x{:04X}", value)
    }
}

pub fn format_register(reg: u8) -> String {
    if let Some(reg) = Register::from_u8(reg) {
        format!("{}", reg.to_str())
    } else {
        format!("R{}", reg)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub compare: CompareFlag,
    pub opcode: Opcode,
    pub a: u8,
    pub b: u8,
    pub c: u16,
}

impl Instruction {
    pub fn new() -> Self {
        Self {
            compare: CompareFlag::None,
            opcode: Opcode::Nop,
            a: 0,
            b: 0,
            c: 0,
        }
    }

    pub fn with_compare(mut self, compare: CompareFlag) -> Self {
        self.compare = compare;
        self
    }

    /// Nop: no operation
    pub fn with_nop(mut self) -> Self {
        self.opcode = Opcode::Nop;
        self
    }

    /// JumpImm: jump to an immediate address
    pub fn with_jump_imm(mut self, addr: u16) -> Self {
        self.opcode = Opcode::JumpImm;
        self.c = addr;
        self
    }

    /// CallImm: call a function at an immediate address
    pub fn with_call_imm(mut self, addr: u16) -> Self {
        self.opcode = Opcode::CallImm;
        self.c = addr;
        self
    }

    /// CallPtr: call a function at a data[addr]
    pub fn with_call_ptr(mut self, addr: Register) -> Self {
        self.opcode = Opcode::CallPtr;
        self.b = addr.to_u8();
        self
    }

    /// Ret: return from function
    pub fn with_return(mut self) -> Self {
        self.opcode = Opcode::Return;
        self
    }

    /// Abort: abort execution with a specific e-rror code
    pub fn with_abort(mut self, code: u16) -> Self {
        self.opcode = Opcode::Abort;
        self.c = code;
        self
    }

    /// Move: copy value from src register to dst register
    pub fn with_move(mut self, dst_register: Register, src_register: Register) -> Self {
        self.opcode = Opcode::Move;
        self.a = dst_register.to_u8();
        self.b = src_register.to_u8();
        self
    }

    /// Load: load register from data address
    pub fn with_load(mut self, dst: Register, addr: u16) -> Self {
        self.opcode = Opcode::Load;
        self.a = dst.to_u8();
        self.c = addr;
        self
    }

    /// Push: push a register onto stack
    pub fn with_push(mut self, src: Register) -> Self {
        self.opcode = Opcode::Push;
        self.b = src.to_u8();
        self
    }

    /// Peek: peek a value from stack with offset
    pub fn with_peek(mut self, dst: Register, offset: Register) -> Self {
        self.opcode = Opcode::Peek;
        self.a = dst.to_u8();
        self.b = offset.to_u8();
        self
    }

    /// Pop: pop a value from stack into a register
    pub fn with_pop(mut self, dst: Register) -> Self {
        self.opcode = Opcode::Pop;
        self.a = dst.to_u8();
        self
    }

    /// StorePtr: store register to data\[addr]
    pub fn with_store_ptr(mut self, src: Register, addr: Register) -> Self {
        self.opcode = Opcode::StorePtr;
        self.a = src.to_u8();
        self.b = addr.to_u8();
        self
    }

    /// LoadPtr: load register from data\[addr]
    pub fn with_load_ptr(mut self, dst: Register, addr: Register) -> Self {
        self.opcode = Opcode::LoadPtr;
        self.a = dst.to_u8();
        self.b = addr.to_u8();
        self
    }

    /// And: bitwise AND operation between two registers
    pub fn with_and(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::And;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// Or: bitwise OR operation between two registers
    pub fn with_or(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::Or;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// Xor: bitwise XOR operation between two registers
    pub fn with_xor(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::Xor;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// Not: bitwise NOT operation on a register
    pub fn with_not(mut self, dst: Register, src: Register) -> Self {
        self.opcode = Opcode::Not;
        self.a = dst.to_u8();
        self.b = src.to_u8();
        self
    }

    /// ShiftL: left shift a register by a constant value
    pub fn with_shift_l(mut self, dst: Register, src: Register, shift: u8) -> Self {
        self.opcode = Opcode::ShiftL;
        self.a = dst.to_u8();
        self.b = src.to_u8();
        self.c = shift as u16;
        self
    }

    /// ShiftR: right shift a register by a constant value
    pub fn with_shift_r(mut self, dst: Register, src: Register, shift: u8) -> Self {
        self.opcode = Opcode::ShiftR;
        self.a = dst.to_u8();
        self.b = src.to_u8();
        self.c = shift as u16;
        self
    }

    /// USet: set a register to an unsigned immediate
    pub fn with_u_set(mut self, dst: Register, value: u16) -> Self {
        self.opcode = Opcode::USet;
        self.a = dst.to_u8();
        self.c = value;
        self
    }

    /// UAdd: add an unsigned immediate to a register
    pub fn with_u_add(mut self, dst: Register, value: u16) -> Self {
        self.opcode = Opcode::UAdd;
        self.a = dst.to_u8();
        self.c = value;
        self
    }

    /// USub: subtract an unsigned immediate from a register
    pub fn with_u_sub(mut self, dst: Register, value: u16) -> Self {
        self.opcode = Opcode::USub;
        self.a = dst.to_u8();
        self.c = value;
        self
    }

    /// IAdd: signed int64 addition between two registers
    pub fn with_i_add(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::IAdd;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// ISub: signed int64 subtraction between two registers
    pub fn with_i_sub(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::ISub;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// IMul: signed int64 multiplication between two registers
    pub fn with_i_mul(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::IMul;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// IDiv: signed int64 division between two registers
    pub fn with_i_div(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::IDiv;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// IRem: signed int64 modulo between two registers
    pub fn with_i_rem(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::IRem;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// ILess: compare two registers for less than
    pub fn with_i_less(mut self, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::ILess;
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// IEqual: compare two registers for equality
    pub fn with_i_equal(mut self, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::IEqual;
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// IGreater: compare two registers for greater than
    pub fn with_i_greater(mut self, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::IGreater;
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FAdd: floating point addition between two registers
    pub fn with_f_add(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FAdd;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FSub: floating point subtraction between two registers
    pub fn with_f_sub(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FSub;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FMul: floating point multiplication between two registers
    pub fn with_f_mul(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FMul;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FDiv: floating point division between two registers
    pub fn with_f_div(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FDiv;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FRem: floating point modulo between two registers
    pub fn with_f_rem(mut self, dst: Register, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FRem;
        self.a = dst.to_u8();
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FLess: compare two registers for floating point less than
    pub fn with_f_less(mut self, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FLess;
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FEqual: compare two registers for floating point equality
    pub fn with_f_equal(mut self, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FEqual;
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FGreater: compare two registers for floating point greater than
    pub fn with_f_greater(mut self, lhs: Register, rhs: Register) -> Self {
        self.opcode = Opcode::FGreater;
        self.b = lhs.to_u8();
        self.c = rhs.to_u8() as u16;
        self
    }

    /// FEpsilon: set epsilon for floating point equal from register
    pub fn with_f_epsilon(mut self, value: Register) -> Self {
        self.opcode = Opcode::FEpsilon;
        self.b = value.to_u8();
        self
    }

    /// CvtI2F: convert an integer register to a floating point register
    pub fn with_cvt_i2f(mut self, dst: Register, src: Register) -> Self {
        self.opcode = Opcode::CvtI2F;
        self.a = dst.to_u8();
        self.b = src.to_u8();
        self
    }

    /// CvtF2I: convert a floating point register to an integer register
    pub fn with_cvt_f2i(mut self, dst: Register, src: Register) -> Self {
        self.opcode = Opcode::CvtF2I;
        self.a = dst.to_u8();
        self.b = src.to_u8();
        self
    }

    /// Syscall: invoke a system call
    pub fn with_syscall(mut self, dst: Register, arg: Register, syscall: Syscall) -> Self {
        self.opcode = Opcode::Syscall;
        self.a = dst.to_u8();
        self.b = arg.to_u8();
        self.c = syscall.to_u16();
        self
    }

    pub fn encode(self) -> [u8; 4] {
        let mut encoded = [0u8; 4];
        encoded[0] = (self.compare as u8) << 6 | (self.opcode.to_u8() & 0b0011_1111);
        encoded[1] = (self.a << 4) | (self.b & 0b0000_1111);
        encoded[2] = (self.c >> 8) as u8;
        encoded[3] = (self.c & 0xFF) as u8;

        encoded
    }

    pub fn decode(encoded: [u8; 4]) -> Option<Self> {
        let compare = CompareFlag::from(encoded[0] >> 6);
        let opcode = Opcode::from_u8(encoded[0] & 0b0011_1111)?;
        let a = encoded[1] >> 4;
        let b = encoded[1] & 0b0000_1111;
        let c = ((encoded[2] as u16) << 8) | (encoded[3] as u16);

        Some(Self {
            compare,
            opcode,
            a,
            b,
            c,
        })
    }

    pub fn disassemble_impl(
        &self,
        omit_jmp_target: bool,
        omit_data_addr_imm: bool,
        omit_data_addr_reg: bool,
    ) -> String {
        let mut res = String::new();

        match self.compare {
            CompareFlag::None => {}
            CompareFlag::True => res.push_str("@t "),
            CompareFlag::False => res.push_str("@f "),
            CompareFlag::Maybe => res.push_str("@m "),
        }

        res.push_str(&self.opcode.to_asm_name());
        res.push(' ');

        match self.opcode {
            Opcode::Nop => {}
            Opcode::JumpImm | Opcode::CallImm => {
                if omit_jmp_target {
                    res.push_str("%JUMP_TARGET%")
                } else {
                    res.push_str(&format_immediate(self.c))
                }
            }
            Opcode::CallPtr => res.push_str(&format_register(self.b)),
            Opcode::Return => {}
            Opcode::Abort => res.push_str(&format_immediate(self.c)),
            Opcode::Move => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.a),
                    format_register(self.b)
                ));
            }
            Opcode::Load => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.a),
                    if omit_data_addr_imm {
                        "%DATA_ADDR_IMM%".to_string()
                    } else {
                        format_immediate(self.c)
                    }
                ));
            }
            Opcode::Push => res.push_str(&format_register(self.b)),
            Opcode::Peek => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.a),
                    format_register(self.b)
                ));
            }
            Opcode::Pop => res.push_str(&format_register(self.a)),
            Opcode::StorePtr => {
                res.push_str(&format!(
                    "{}, {}",
                    if omit_data_addr_reg {
                        "%DATA_ADDR_REG%".to_string()
                    } else {
                        format_register(self.a)
                    },
                    format_register(self.b),
                ));
            }
            Opcode::LoadPtr => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.a),
                    if omit_data_addr_reg {
                        "%DATA_ADDR_REG%".to_string()
                    } else {
                        format_register(self.b)
                    }
                ));
            }
            Opcode::And
            | Opcode::Or
            | Opcode::Xor
            | Opcode::Not
            | Opcode::ShiftL
            | Opcode::ShiftR => {
                res.push_str(&format!(
                    "{}, {}, {}",
                    format_register(self.a),
                    format_register(self.b),
                    format_register(self.c as u8)
                ));
            }
            Opcode::USet | Opcode::UAdd | Opcode::USub => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.a),
                    format_immediate(self.c)
                ));
            }
            Opcode::IAdd | Opcode::ISub | Opcode::IMul | Opcode::IDiv | Opcode::IRem => {
                res.push_str(&format!(
                    "{}, {}, {}",
                    format_register(self.a),
                    format_register(self.b),
                    format_register(self.c as u8)
                ));
            }
            Opcode::ILess | Opcode::IEqual | Opcode::IGreater => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.b),
                    format_register(self.c as u8)
                ));
            }
            Opcode::FAdd | Opcode::FSub | Opcode::FMul | Opcode::FDiv | Opcode::FRem => {
                res.push_str(&format!(
                    "{}, {}, {}",
                    format_register(self.a),
                    format_register(self.b),
                    format_register(self.c as u8)
                ));
            }
            Opcode::FLess | Opcode::FEqual | Opcode::FGreater => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.b),
                    format_register(self.c as u8)
                ));
            }
            Opcode::FEpsilon => res.push_str(&format_register(self.b)),
            Opcode::CvtI2F | Opcode::CvtF2I => {
                res.push_str(&format!(
                    "{}, {}",
                    format_register(self.a),
                    format_register(self.b)
                ));
            }
            Opcode::Syscall => {
                res.push_str(&format!(
                    "{}, {}, {}",
                    format_register(self.a),
                    format_register(self.b),
                    Syscall::from_u16(self.c)
                        .map_or(format_immediate(self.c), |s| s.to_asm_name().to_string())
                ));
            }
        }

        res
    }

    pub fn disassemble(&self) -> String {
        self.disassemble_impl(false, false, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_encode_decode() {
        let insn = Instruction::new()
            .with_compare(CompareFlag::True)
            .with_shift_l(Register::R0, Register::R1, 5);

        let encoded = insn.encode();
        println!("Encoded instruction: {:?}", encoded);

        let decoded = Instruction::decode(encoded).expect("Failed to decode instruction");

        assert_eq!(decoded.compare, CompareFlag::True);
        assert_eq!(decoded.opcode, Opcode::ShiftL);
        assert_eq!(decoded.a, Register::R0.to_u8());
        assert_eq!(decoded.b, Register::R1.to_u8());
        assert_eq!(decoded.c, 5);
    }

    #[test]
    fn test_instruction_disassemble() {
        let insn = Instruction::new()
            .with_compare(CompareFlag::False)
            .with_jump_imm(1239);

        println!("{:#?}", insn);
        println!("assem: {:02X?}", insn.encode());

        let disassembled = insn.disassemble_impl(false, false, false);
        println!("disas: {}", disassembled);
    }
}
