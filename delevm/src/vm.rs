use crate::{opcodes::Opcode, syscall::Syscall};

#[repr(C)]
#[derive(Clone, Copy)]
pub union Value {
    pub int64: i64,
    pub float64: f64,
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe { write!(f, "Value(i64: {}, f64: {})", self.int64, self.float64) }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareFlag {
    None = 0b00,
    True = 0b01,
    False = 0b10,
    Maybe = 0b11,
}

impl From<u8> for CompareFlag {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0 => CompareFlag::None,
            1 => CompareFlag::True,
            2 => CompareFlag::False,
            3 => CompareFlag::Maybe,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleVMError {
    InvalidOpcode(u8),
    InvalidRegister(usize),
    InvalidAddress(usize),
    StackOverflow(usize),
    StackUnderflow(usize),
    DivideByZero,
    Abort,
    InvalidSyscall(u16),
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    RSP = 12, // stack pointer
    RIP = 13, // program counter
    RCM = 14, // comparison register
    REP = 15, // epsilon register
}

impl Register {
    pub fn from_u8(value: u8) -> Option<Register> {
        match value {
            0 => Some(Register::R0),
            1 => Some(Register::R1),
            2 => Some(Register::R2),
            3 => Some(Register::R3),
            4 => Some(Register::R4),
            5 => Some(Register::R5),
            6 => Some(Register::R6),
            7 => Some(Register::R7),
            8 => Some(Register::R8),
            9 => Some(Register::R9),
            10 => Some(Register::R10),
            11 => Some(Register::R11),
            12 => Some(Register::RSP),
            13 => Some(Register::RIP),
            14 => Some(Register::RCM),
            15 => Some(Register::REP),
            _ => None,
        }
    }

    pub fn from_str(name: &str) -> Option<Register> {
        match name {
            "R0" | "0" => Some(Register::R0),
            "R1" | "1" => Some(Register::R1),
            "R2" | "2" => Some(Register::R2),
            "R3" | "3" => Some(Register::R3),
            "R4" | "4" => Some(Register::R4),
            "R5" | "5" => Some(Register::R5),
            "R6" | "6" => Some(Register::R6),
            "R7" | "7" => Some(Register::R7),
            "R8" | "8" => Some(Register::R8),
            "R9" | "9" => Some(Register::R9),
            "R10" | "10" => Some(Register::R10),
            "R11" | "11" => Some(Register::R11),
            "RSP" | "SP" | "R12" | "12" => Some(Register::RSP),
            "RIP" | "IP" | "R13" | "13" => Some(Register::RIP),
            "RCM" | "CM" | "R14" | "14" => Some(Register::RCM),
            "REP" | "EP" | "R15" | "15" => Some(Register::REP),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Register::R0 => "R0",
            Register::R1 => "R1",
            Register::R2 => "R2",
            Register::R3 => "R3",
            Register::R4 => "R4",
            Register::R5 => "R5",
            Register::R6 => "R6",
            Register::R7 => "R7",
            Register::R8 => "R8",
            Register::R9 => "R9",
            Register::R10 => "R10",
            Register::R11 => "R11",
            Register::RSP => "RSP",
            Register::RIP => "RIP",
            Register::RCM => "RCM",
            Register::REP => "REP",
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

pub const STACK_REG: usize = Register::RSP as usize;
pub const INSTRUCTION_REG: usize = Register::RIP as usize;
pub const COMPARISON_REG: usize = Register::RCM as usize;
pub const EPSILON_REG: usize = Register::REP as usize;

pub struct DeleVM {
    pub data: Box<[Value; 65536]>,
    pub code: Box<[u32; 65536]>,
    pub stack: Box<[Value; 65536]>,
    pub registers: [Value; 16],
}

impl DeleVM {
    pub fn new() -> Self {
        DeleVM {
            data: Box::new([Value { int64: 0 }; 65536]),
            code: Box::new([0; 65536]),
            stack: Box::new([Value { int64: 0 }; 65536]),
            registers: [Value { int64: 0 }; 16],
        }
    }

    pub fn reset(&mut self) {
        self.registers = [Value { int64: 0 }; 16];
    }

    fn read_code(&self, addr: usize) -> Result<u32, DeleVMError> {
        if addr >= self.code.len() {
            return Err(DeleVMError::InvalidAddress(addr));
        }

        Ok(self.code[addr])
    }

    fn read_reg_i64(&self, reg: usize) -> Result<i64, DeleVMError> {
        if reg >= self.registers.len() {
            return Err(DeleVMError::InvalidRegister(reg));
        }

        unsafe { Ok(self.registers[reg].int64) }
    }

    fn read_reg_f64(&self, reg: usize) -> Result<f64, DeleVMError> {
        if reg >= self.registers.len() {
            return Err(DeleVMError::InvalidRegister(reg));
        }

        unsafe { Ok(self.registers[reg].float64) }
    }

    fn write_reg_i64(&mut self, reg: usize, value: i64) -> Result<(), DeleVMError> {
        if reg >= self.registers.len() {
            return Err(DeleVMError::InvalidRegister(reg));
        }

        self.registers[reg].int64 = value;

        Ok(())
    }

    fn write_reg_f64(&mut self, reg: usize, value: f64) -> Result<(), DeleVMError> {
        if reg >= self.registers.len() {
            return Err(DeleVMError::InvalidRegister(reg));
        }

        self.registers[reg].float64 = value;

        Ok(())
    }

    fn read_data_i64(&self, addr: usize) -> Result<i64, DeleVMError> {
        if addr >= self.data.len() {
            return Err(DeleVMError::InvalidAddress(addr));
        }

        unsafe { Ok(self.data[addr].int64) }
    }

    fn read_data_f64(&self, addr: usize) -> Result<f64, DeleVMError> {
        if addr >= self.data.len() {
            return Err(DeleVMError::InvalidAddress(addr));
        }

        unsafe { Ok(self.data[addr].float64) }
    }

    fn write_data_i64(&mut self, addr: usize, value: i64) -> Result<(), DeleVMError> {
        if addr >= self.data.len() {
            return Err(DeleVMError::InvalidAddress(addr));
        }

        self.data[addr].int64 = value;

        Ok(())
    }

    fn write_data_f64(&mut self, addr: usize, value: f64) -> Result<(), DeleVMError> {
        if addr >= self.data.len() {
            return Err(DeleVMError::InvalidAddress(addr));
        }

        self.data[addr].float64 = value;

        Ok(())
    }

    fn stack_push_i64(&mut self, value: i64) -> Result<(), DeleVMError> {
        let stack_ptr = self.read_reg_i64(STACK_REG)? as usize;

        if stack_ptr >= self.stack.len() {
            return Err(DeleVMError::StackOverflow(stack_ptr));
        }

        self.stack[stack_ptr].int64 = value;
        self.write_reg_i64(STACK_REG, (stack_ptr + 1) as i64)?;

        Ok(())
    }

    fn stack_pop_i64(&mut self) -> Result<i64, DeleVMError> {
        let stack_ptr = self.read_reg_i64(STACK_REG)? as usize;

        if stack_ptr == 0 {
            return Err(DeleVMError::StackUnderflow(stack_ptr));
        }

        let value = unsafe { self.stack[stack_ptr - 1].int64 };
        self.write_reg_i64(STACK_REG, (stack_ptr - 1) as i64)?;

        Ok(value)
    }

    fn stack_push_f64(&mut self, value: f64) -> Result<(), DeleVMError> {
        let stack_ptr = self.read_reg_i64(STACK_REG)? as usize;

        if stack_ptr >= self.stack.len() {
            return Err(DeleVMError::StackOverflow(stack_ptr));
        }

        self.stack[stack_ptr].float64 = value;
        self.write_reg_i64(STACK_REG, (stack_ptr + 1) as i64)?;

        Ok(())
    }

    fn stack_pop_f64(&mut self) -> Result<f64, DeleVMError> {
        let stack_ptr = self.read_reg_i64(STACK_REG)? as usize;

        if stack_ptr == 0 {
            return Err(DeleVMError::StackUnderflow(stack_ptr));
        }

        let value = unsafe { self.stack[stack_ptr - 1].float64 };
        self.write_reg_i64(STACK_REG, (stack_ptr - 1) as i64)?;

        Ok(value)
    }

    fn stack_peek_i64(&self, offset: usize) -> Result<i64, DeleVMError> {
        let stack_ptr = self.read_reg_i64(STACK_REG)? as usize;

        if stack_ptr <= offset {
            return Err(DeleVMError::StackUnderflow(stack_ptr));
        }

        let value = unsafe { self.stack[stack_ptr - 1 - offset].int64 };
        Ok(value)
    }

    fn stack_peek_f64(&self, offset: usize) -> Result<f64, DeleVMError> {
        let stack_ptr = self.read_reg_i64(STACK_REG)? as usize;

        if stack_ptr <= offset {
            return Err(DeleVMError::StackUnderflow(stack_ptr));
        }

        let value = unsafe { self.stack[stack_ptr - 1 - offset].float64 };
        Ok(value)
    }

    fn execute_instruction(
        &mut self,
        opcode: u8,
        a: u8,
        b: u8,
        c: u16,
    ) -> Result<Option<Value>, DeleVMError> {
        #[cfg(debug_assertions)]
        {
            println!(
                "[VM] Executing opcode: {:02X} {:?} (a: {}, b: {}, c: {})",
                opcode,
                Opcode::from_u8(opcode),
                a,
                b,
                c
            );
        }

        match Opcode::from_u8(opcode) {
            Some(Opcode::JumpImm) => {
                self.write_reg_i64(INSTRUCTION_REG, c as i64)?;

                Ok(None)
            }

            Some(Opcode::CallImm) => {
                let current_pc = self.read_reg_i64(INSTRUCTION_REG)? as usize;

                self.stack_push_i64(current_pc as i64)?;
                self.write_reg_i64(INSTRUCTION_REG, c as i64)?;

                Ok(None)
            }

            Some(Opcode::CallPtr) => {
                let addr = self.read_reg_i64(b as usize)? as usize;

                if addr >= self.code.len() {
                    return Err(DeleVMError::InvalidAddress(addr));
                }

                let current_pc = self.read_reg_i64(INSTRUCTION_REG)? as usize;

                self.stack_push_i64(current_pc as i64)?;
                self.write_reg_i64(INSTRUCTION_REG, addr as i64)?;

                Ok(None)
            }

            Some(Opcode::Return) => {
                let return_pc = self.stack_pop_i64()?;

                if return_pc < 0 || return_pc >= self.code.len() as i64 {
                    return Err(DeleVMError::InvalidAddress(return_pc as usize));
                }

                self.write_reg_i64(INSTRUCTION_REG, return_pc)?;

                Ok(None)
            }

            Some(Opcode::Abort) => Err(DeleVMError::Abort),

            Some(Opcode::Move) => {
                let value = self.read_reg_i64(a as usize)?;
                self.write_reg_i64(b as usize, value)?;

                Ok(None)
            }

            Some(Opcode::Load) => {
                let value = self.read_data_i64(c as usize)?;
                self.write_reg_i64(a as usize, value)?;

                Ok(None)
            }

            Some(Opcode::Push) => {
                self.stack_push_i64(self.read_reg_i64(b as usize)?)?;

                Ok(None)
            }

            Some(Opcode::Peek) => {
                self.write_reg_i64(b as usize, self.stack_peek_i64(a as usize)?)?;

                Ok(None)
            }

            Some(Opcode::Pop) => {
                let value = self.stack_pop_i64()?;
                self.write_reg_i64(a as usize, value)?;

                Ok(None)
            }

            Some(Opcode::StorePtr) => {
                let dst = self.read_reg_i64(b as usize)? as usize;
                self.write_data_i64(dst, self.read_reg_i64(a as usize)?)?;

                Ok(None)
            }

            Some(Opcode::LoadPtr) => {
                let stc = self.read_reg_i64(b as usize)? as usize;
                let value = self.read_data_i64(stc)?;
                self.write_reg_i64(a as usize, value)?;

                Ok(None)
            }

            Some(Opcode::And) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                self.write_reg_i64(a as usize, lhs & rhs)?;

                Ok(None)
            }

            Some(Opcode::Or) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                self.write_reg_i64(a as usize, lhs | rhs)?;

                Ok(None)
            }

            Some(Opcode::Xor) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                self.write_reg_i64(a as usize, lhs ^ rhs)?;

                Ok(None)
            }

            Some(Opcode::Not) => {
                let value = self.read_reg_i64(b as usize)?;
                self.write_reg_i64(a as usize, !value)?;

                Ok(None)
            }

            Some(Opcode::ShiftL) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                if rhs < 0 || rhs >= 64 {
                    return Err(DeleVMError::InvalidOpcode(opcode));
                }
                self.write_reg_i64(a as usize, lhs << rhs)?;

                Ok(None)
            }

            Some(Opcode::ShiftR) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                if rhs < 0 || rhs >= 64 {
                    return Err(DeleVMError::InvalidOpcode(opcode));
                }
                self.write_reg_i64(a as usize, lhs >> rhs)?;

                Ok(None)
            }

            Some(Opcode::USet) => {
                let value: i16 = unsafe { std::mem::transmute(c) };
                self.write_reg_i64(a as usize, value as i64)?;

                Ok(None)
            }

            Some(Opcode::UAdd) => {
                let value = self.read_reg_i64(a as usize)? as u64 + (c as u64);
                self.write_reg_i64(a as usize, value as i64)?;

                Ok(None)
            }

            Some(Opcode::USub) => {
                let value = self.read_reg_i64(a as usize)? as u64 - (c as u64);
                self.write_reg_i64(a as usize, value as i64)?;

                Ok(None)
            }

            Some(Opcode::IAdd) => {
                let lhs = self.read_reg_i64(a as usize)?;
                let rhs = self.read_reg_i64(b as usize)?;
                self.write_reg_i64(a as usize, lhs + rhs)?;

                Ok(None)
            }

            Some(Opcode::ISub) => {
                let lhs = self.read_reg_i64(a as usize)?;
                let rhs = self.read_reg_i64(b as usize)?;
                self.write_reg_i64(a as usize, lhs - rhs)?;

                Ok(None)
            }

            Some(Opcode::IMul) => {
                let lhs = self.read_reg_i64(a as usize)?;
                let rhs = self.read_reg_i64(b as usize)?;
                self.write_reg_i64(a as usize, lhs * rhs)?;

                Ok(None)
            }

            Some(Opcode::IDiv) => {
                let lhs = self.read_reg_i64(a as usize)?;
                let rhs = self.read_reg_i64(b as usize)?;

                if rhs == 0 {
                    return Err(DeleVMError::DivideByZero);
                }
                self.write_reg_i64(a as usize, lhs / rhs)?;

                Ok(None)
            }

            Some(Opcode::IRem) => {
                let lhs = self.read_reg_i64(a as usize)?;
                let rhs = self.read_reg_i64(b as usize)?;

                if rhs == 0 {
                    return Err(DeleVMError::DivideByZero);
                }
                self.write_reg_i64(a as usize, lhs % rhs)?;

                Ok(None)
            }

            Some(Opcode::ILess) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                self.write_reg_i64(COMPARISON_REG, if lhs < rhs { 1 } else { 0 })?;

                Ok(None)
            }

            Some(Opcode::IEqual) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                self.write_reg_i64(COMPARISON_REG, if lhs == rhs { 1 } else { 0 })?;

                Ok(None)
            }

            Some(Opcode::IGreater) => {
                let lhs = self.read_reg_i64(b as usize)?;
                let rhs = self.read_reg_i64(c as usize)?;
                self.write_reg_i64(COMPARISON_REG, if lhs > rhs { 1 } else { 0 })?;

                Ok(None)
            }

            Some(Opcode::FAdd) => {
                let lhs = self.read_reg_f64(a as usize)?;
                let rhs = self.read_reg_f64(b as usize)?;
                self.write_reg_f64(a as usize, lhs + rhs)?;

                Ok(None)
            }

            Some(Opcode::FSub) => {
                let lhs = self.read_reg_f64(a as usize)?;
                let rhs = self.read_reg_f64(b as usize)?;
                self.write_reg_f64(a as usize, lhs - rhs)?;

                Ok(None)
            }

            Some(Opcode::FMul) => {
                let lhs = self.read_reg_f64(a as usize)?;
                let rhs = self.read_reg_f64(b as usize)?;
                self.write_reg_f64(a as usize, lhs * rhs)?;

                Ok(None)
            }

            Some(Opcode::FDiv) => {
                let lhs = self.read_reg_f64(a as usize)?;
                let rhs = self.read_reg_f64(b as usize)?;

                if rhs == 0.0 {
                    return Err(DeleVMError::DivideByZero);
                }
                self.write_reg_f64(a as usize, lhs / rhs)?;

                Ok(None)
            }

            Some(Opcode::FRem) => {
                let lhs = self.read_reg_f64(a as usize)?;
                let rhs = self.read_reg_f64(b as usize)?;

                if rhs == 0.0 {
                    return Err(DeleVMError::DivideByZero);
                }
                self.write_reg_f64(a as usize, lhs % rhs)?;

                Ok(None)
            }

            Some(Opcode::FLess) => {
                let lhs = self.read_reg_f64(b as usize)?;
                let rhs = self.read_reg_f64(c as usize)?;
                self.write_reg_i64(COMPARISON_REG, if lhs < rhs { 1 } else { 0 })?;

                Ok(None)
            }

            Some(Opcode::FEqual) => {
                let lhs = self.read_reg_f64(b as usize)?;
                let rhs = self.read_reg_f64(c as usize)?;
                self.write_reg_i64(
                    COMPARISON_REG,
                    if (lhs - rhs).abs() < self.read_reg_f64(EPSILON_REG)? {
                        1
                    } else {
                        0
                    },
                )?;

                Ok(None)
            }

            Some(Opcode::FGreater) => {
                let lhs = self.read_reg_f64(b as usize)?;
                let rhs = self.read_reg_f64(c as usize)?;
                self.write_reg_i64(COMPARISON_REG, if lhs > rhs { 1 } else { 0 })?;

                Ok(None)
            }

            Some(Opcode::FEpsilon) => {
                let value = self.read_reg_f64(b as usize)?;
                self.write_reg_f64(EPSILON_REG, value)?;

                Ok(None)
            }

            Some(Opcode::CvtI2F) => {
                let value = self.read_reg_i64(b as usize)?;
                self.write_reg_f64(a as usize, value as f64)?;

                Ok(None)
            }

            Some(Opcode::CvtF2I) => {
                let value = self.read_reg_f64(b as usize)?;
                self.write_reg_i64(a as usize, value as i64)?;

                Ok(None)
            }

            Some(Opcode::Syscall) => {
                let syscall = Syscall::from_u16(c).ok_or(DeleVMError::InvalidSyscall(c))?;

                // can be float arg too, but doesnt matter since
                // we just care about the bits
                let arg = self.read_reg_i64(b as usize)?;

                let result = syscall.execute(self, Value { int64: arg })?;
                self.write_reg_i64(a as usize, unsafe { result.int64 })?;

                Ok(None)
            }
            _ => Err(DeleVMError::InvalidOpcode(opcode)),
        }
    }

    pub fn step(&mut self) -> Result<Option<Value>, DeleVMError> {
        let pc = self.read_reg_i64(INSTRUCTION_REG)? as usize;

        if pc >= self.code.len() {
            return Err(DeleVMError::InvalidAddress(pc));
        }

        self.write_reg_i64(INSTRUCTION_REG, (pc + 1) as i64)?;

        let instruction = self.read_code(pc)?;

        let cmp = CompareFlag::from(((instruction >> 30) & 0b11) as u8);
        let opcode = (instruction >> 24) & 0b0011_1111;

        let a = (instruction >> 20) & 0b1111;
        let b = (instruction >> 16) & 0b1111;
        let c = (instruction) & 0b1111_1111_1111_1111;

        if matches!(cmp, CompareFlag::Maybe) {
            // todo: maybe probability flag
            self.write_reg_i64(COMPARISON_REG, (rand::random::<f64>() < 0.5) as i64)?;
        }

        let cmp = if matches!(cmp, CompareFlag::Maybe) {
            CompareFlag::True
        } else {
            cmp
        };

        match (cmp, self.read_reg_i64(COMPARISON_REG)? != 0) {
            (CompareFlag::None, _) | (CompareFlag::False, false) | (CompareFlag::True, true) => {
                self.execute_instruction(opcode as u8, a as u8, b as u8, c as u16)
            }
            _ => Ok(None),
        }
    }
}
