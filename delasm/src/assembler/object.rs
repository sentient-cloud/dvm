pub enum SymbolKind {
    Metadata,    // metadata about the object
    Static,      // static symbol, with a fixed address
    Relocatable, // symbol that needs to be resolved later
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {}
