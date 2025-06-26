use crate::vm::{DeleVM, DeleVMError, Value};

macro_rules! define_syscalls {
    ($($name:ident($asmname:ident) = $value:expr => $func:expr),* $(,)?) => {
        #[repr(u16)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Syscall {
            $($name = $value),*
        }

        impl Syscall {
            pub fn from_u16(code: u16) -> Option<Syscall> {
                match code {
                    $($value => Some(Syscall::$name),)*
                    _ => None,
                }
            }

            pub fn to_u16(self) -> u16 {
                self as u16
            }

            pub fn to_str(self) -> &'static str {
                match self {
                    $(Syscall::$name => stringify!($name),)*
                }
            }

            pub fn to_asm_name(self) -> &'static str {
                match self {
                    $(Syscall::$name => stringify!($asmname),)*
                }
            }

            pub fn from_asm_name(name: &str) -> Option<Syscall> {
                match name {
                    $(stringify!($asmname) => Some(Syscall::$name),)*
                    _ => None,
                }
            }

            pub fn execute(self, vm: &mut DeleVM, arg1: Value) -> Result<Value, DeleVMError> {
                match self {
                    $(Syscall::$name => $func(vm, arg1),)*
                }
            }
        }
    };
}

define_syscalls!(
    DumpRegisters(dump_registers) = 0x0000 => |vm: &mut DeleVM, _arg1| {
        println!("[syscall] dump registers:");
        for (i, reg) in vm.registers.iter().enumerate() {
            println!("  R{}: {:?}", i, reg);
        }
        Ok(Value { int64: 0 })
    },
    PrintI64(print_i64) = 0x0001 => |_vm: &mut DeleVM, arg1: Value| {
        let value = unsafe { arg1.int64 };
        println!("[syscall] print_i64: {}", value);
        Ok(Value { int64: 0 })
    },
    PrintF64(print_f64) = 0x0002 => |_vm: &mut DeleVM, arg1: Value| {
        let value = unsafe { arg1.float64 };
        println!("[syscall] print_f64: {}", value);
        Ok(Value { int64: 0 })
    },
    PrintString(print_string) = 0x0003 => |vm: &mut DeleVM, arg1: Value| {
        let mut addr = unsafe { arg1.int64 } as usize;
        loop {
            if addr >= vm.data.len() {
                return Err(DeleVMError::InvalidAddress(addr));
            }

            let bytes = unsafe { std::mem::transmute::<i64, u64>(vm.data[addr].int64) };
            let bytes = bytes.to_be_bytes();

            for &byte in &bytes {
                if byte == 0 {
                    println!();
                    return Ok(Value { int64: 0 });
                }
                print!("{}", byte as char);
            }

            addr += 1;
        }
    }
);
