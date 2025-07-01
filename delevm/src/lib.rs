// meow

pub mod opcodes;
pub mod syscall;
pub mod vm;

pub use opcodes::Opcode;
pub use syscall::Syscall;
pub use vm::DeleVM;
