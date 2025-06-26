macro_rules! define_opcodes {
    ($($name:ident($asm_name:ident) = $value:expr),* $(,)?) => {
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Opcode {
            $($name = $value),*
        }

        impl Opcode {
            pub fn from_u8(opcode: u8) -> Option<Opcode> {
                match opcode {
                    $($value => Some(Opcode::$name),)*
                    _ => None,
                }
            }

            pub fn to_str(self) -> &'static str {
                match self {
                    $(Opcode::$name => stringify!($name),)*
                }
            }

            pub fn from_str(name: &str) -> Option<Opcode> {
                match name {
                    $(stringify!($name) => Some(Opcode::$name),)*
                    _ => None,
                }
            }

            pub fn to_asm_name(self) -> &'static str {
                match self {
                    $(Opcode::$name => stringify!($asm_name),)*
                }
            }

            pub fn from_asm_name(name: &str) -> Option<Opcode> {
                match name {
                    $(stringify!($asm_name) => Some(Opcode::$name),)*
                    _ => None,
                }
            }

            pub fn to_u8(self) -> u8 {
                self as u8
            }
        }
    };
}

define_opcodes!(
    Nop(nop) = 0b0000_0000,
    JumpImm(jump) = 0b0000_0001,
    CallImm(call) = 0b0000_0010,
    CallPtr(callp) = 0b0000_0011,
    Return(ret) = 0b0000_0100,
    Abort(abort) = 0b0000_0101,
    Move(mov) = 0b0000_1000,
    Load(load) = 0b0000_1001,
    Push(push) = 0b0000_1010,
    Peek(peek) = 0b0000_1011,
    Pop(pop) = 0b0000_1100,
    StorePtr(storp) = 0b0000_1101,
    LoadPtr(loadp) = 0b0000_1110,
    And(and) = 0b0001_0000,
    Or(or) = 0b0001_0001,
    Xor(xor) = 0b0001_0010,
    Not(not) = 0b0001_0011,
    ShiftL(shfl) = 0b0001_0100,
    ShiftR(shfr) = 0b0001_0101,
    USet(uset) = 0b0001_0110,
    UAdd(uadd) = 0b0001_0111,
    USub(usub) = 0b0001_1000,
    IAdd(iadd) = 0b0001_1001,
    ISub(isub) = 0b0001_1010,
    IMul(imul) = 0b0001_1011,
    IDiv(idiv) = 0b0001_1100,
    IRem(irem) = 0b0001_1101,
    ILess(iles) = 0b0001_1110,
    IEqual(iequ) = 0b0001_1111,
    IGreater(igrt) = 0b0010_0000,
    FAdd(fadd) = 0b0010_0001,
    FSub(fsub) = 0b0010_0010,
    FMul(fmul) = 0b0010_0011,
    FDiv(fdiv) = 0b0010_0100,
    FRem(frem) = 0b0010_0101,
    FLess(fles) = 0b0010_0110,
    FEqual(fequ) = 0b0010_0111,
    FGreater(fgrt) = 0b0010_1000,
    FEpsilon(feps) = 0b0010_1001,
    CvtI2F(cvti2f) = 0b0010_1010,
    CvtF2I(cvtf2i) = 0b0010_1011,
    Syscall(syscall) = 0b0011_1111,
);
