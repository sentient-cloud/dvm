/*
DelASM Object File Format:

header:
    'dvmo'  (4 bytes)
    version (4 bytes, u32)
    flags   (8 bytes, u64)
    chunk_count  (4 bytes, u32)
    chunk_offset (8 bytes, u64)
        (offset to the first chunk, relative to the start of the file)

chunk: (align 8)
    type (4 bytes, u32)
        1: metadata
        2: symbols
        3: relocations
        4: section
    data_len  (4 bytes, u32)
    data (variable length)

    (next chunk...)

    // there must be 0 or 1 of metadata, 1 of symbols, and 0 or 1 of relocation chunks,
    // and at least 1 section chunk.

metadata chunk: (align 8)
    key (variable length ascii string, zero terminated)
    length: (4 bytes, u32, align 8)
    value: (variable length, align 8)

    (repeated until the end of the chunk)

symbols chunk: (align 8)
    type (1 byte, u8)
        1: code (function addr, or addr of a label)
        2: data (addr of a label)
    linkage (1 byte, u8)
        1: internal (in this object file, not exported)
        2: export   (in this object file, exported)
        3: external (not in this object file)
    offset (8 bytes, u64, align 8)
        (address of the symbol relative to the start of the section)
    section_name (variable length ascii string, zero terminated)
        (optional, assumed to be "code" for code symbols and "data" for data symbols)
    name (variable length ascii string, zero terminated)
        (optional, if not provided, the symbol is unnamed,
         and is referenced by the section name)

    (repeated until the end of the chunk)

relocations chunk: (align 8)
    type (1 byte, u8)
        1: absolute
        2: relative
    symbol (variable length ascii string, zero terminated)
        (the symbol name to apply the relocation to)
    offset (8 bytes, u64, align 8)
        (address of the relocation relative to the start of the symbol)
    addend (8 bytes, i64, align 8)

    (repeated until the end of the chunk)

    // absolute relocations:
    //     1. look up symbol by the name
    //     2. compute relocation address as symbol address + addend
    //     3. write the address to the offset

section chunk: (align 8)
    type (4 bytes, u32)
        1: code
        2: data
    address (2 bytes, u16, align 4)
        (if set to 0xFFFF, section must be given an address by the linker)
    name (variable length ascii string, zero terminated)
        (optional, if not provided assumed to be "code" for
         code sections and "data" for data sections)
    data_size (8 bytes, u64, align 8)
    data (variable length, align 8)
*/

#[derive(Debug, Clone)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u32,
    pub flags: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    Metadata = 1,
    Symbols = 2,
    Relocations = 3,
    Section = 4,
}

impl ChunkKind {
    pub fn is_metadata(self) -> bool {
        self == ChunkKind::Metadata
    }

    pub fn is_symbols(self) -> bool {
        self == ChunkKind::Symbols
    }

    pub fn is_relocations(self) -> bool {
        self == ChunkKind::Relocations
    }

    pub fn is_section(self) -> bool {
        self == ChunkKind::Section
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(ChunkKind::Metadata),
            2 => Some(ChunkKind::Symbols),
            3 => Some(ChunkKind::Relocations),
            4 => Some(ChunkKind::Section),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Code = 1, // Function address or label address
    Data = 2, // Label address
}

impl SymbolKind {
    pub fn is_code(self) -> bool {
        self == SymbolKind::Code
    }

    pub fn is_data(self) -> bool {
        self == SymbolKind::Data
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(SymbolKind::Code),
            2 => Some(SymbolKind::Data),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolLinkage {
    Internal = 1, // In this object file, not exported
    Export = 2,   // In this object file, exported
    External = 3, // Not in this object file
}

impl SymbolLinkage {
    pub fn is_internal(self) -> bool {
        self == SymbolLinkage::Internal
    }

    pub fn is_export(self) -> bool {
        self == SymbolLinkage::Export
    }

    pub fn is_external(self) -> bool {
        self == SymbolLinkage::External
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(SymbolLinkage::Internal),
            2 => Some(SymbolLinkage::Export),
            3 => Some(SymbolLinkage::External),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub symbol_kind: SymbolKind,
    pub linkage: SymbolLinkage,
    pub offset: u64,
    pub section_name: Option<String>,
    pub name: Option<String>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationKind {
    Absolute = 1,
    Relative = 2,
}

impl RelocationKind {
    pub fn is_absolute(self) -> bool {
        self == RelocationKind::Absolute
    }

    pub fn is_relative(self) -> bool {
        self == RelocationKind::Relative
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(RelocationKind::Absolute),
            2 => Some(RelocationKind::Relative),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub relocation_kind: RelocationKind,
    pub symbol: String,
    pub offset: u64,
    pub addend: i64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Code = 1,
    Data = 2,
}

impl SectionKind {
    pub fn is_code(self) -> bool {
        self == SectionKind::Code
    }

    pub fn is_data(self) -> bool {
        self == SectionKind::Data
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(SectionKind::Code),
            2 => Some(SectionKind::Data),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub section_kind: SectionKind,
    pub address: u16,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ObjectError {
    InvalidMagic(String),
    UnsupportedVersion(String),
    InvalidChunkKind(String),
    InvalidSymbolKind(String),
    InvalidSymbolLinkage(String),
    InvalidSymbolName(String),
    InvalidRelocationKind(String),
    InvalidSectionKind(String),
    InvalidSectionName(String),
    InvalidMetadataKey(String),
    InsufficientData(String),
}

#[derive(Debug, Clone)]
pub struct Object {
    pub header: Header,
    pub metadata: Vec<(String, Vec<u8>)>, // (key, value)
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub sections: Vec<Section>,
}

pub const OBJECT_MAGIC: [u8; 4] = *b"dvmo";
pub const OBJECT_VERSION: u32 = 1;

impl Object {
    pub fn new() -> Self {
        Object {
            header: Header {
                magic: OBJECT_MAGIC,
                version: OBJECT_VERSION,
                flags: 0,
            },
            metadata: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            sections: Vec::new(),
        }
    }

    pub fn merge(mut self, other: Object) -> Self {
        // TODO: handle collisions in everything
        self.metadata.extend(other.metadata);
        self.symbols.extend(other.symbols);
        self.relocations.extend(other.relocations);
        self.sections.extend(other.sections);
        self
    }

    pub fn from_u8_slice(data: &[u8]) -> Result<Self, ObjectError> {
        let mut res = Object {
            header: Header {
                magic: [0; 4],
                version: 0,
                flags: 0,
            },
            metadata: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            sections: Vec::new(),
        };

        fn chop(slice: &[u8], at: usize) -> Result<(&[u8], &[u8]), ObjectError> {
            if slice.len() < at {
                return Err(ObjectError::InsufficientData(format!(
                    "Expected at least {} bytes, got {}",
                    at,
                    slice.len()
                )));
            }
            Ok(slice.split_at(at))
        }

        fn chop_stringz(slice: &[u8]) -> Result<(&[u8], &[u8]), ObjectError> {
            if let Some(pos) = slice.iter().position(|&b| b == 0) {
                Ok(slice.split_at(pos + 1)) // include null terminator
            } else {
                Err(ObjectError::InsufficientData(
                    "Expected null-terminated string, zero terminator not found".to_string(),
                ))
            }
        }

        fn align(addr: usize, alignment: usize) -> usize {
            (addr + alignment - 1) & !(alignment - 1)
        }

        fn align_slice<'a>(
            base: &'a [u8],
            current: &'a [u8],
            alignment: usize,
        ) -> Result<&'a [u8], ObjectError> {
            let base_ptr = base.as_ptr() as usize;
            let current_ptr = current.as_ptr() as usize;

            assert!(current_ptr >= base_ptr); // hurrdurr

            let offset = current_ptr - base_ptr;
            let aligned = align(offset, alignment);
            let aligned_ptr = base_ptr + aligned;

            if aligned_ptr > base_ptr + base.len() {
                return Err(ObjectError::InsufficientData(format!(
                    "Aligned pointer {:x} is beyond the end of the data (base: {:x}, len: {})",
                    aligned_ptr,
                    base_ptr,
                    base.len()
                )));
            }

            Ok(&base[(aligned_ptr - base_ptr)..])
        }

        let (magic, rest) = chop(data, 4)?;
        if magic != OBJECT_MAGIC {
            return Err(ObjectError::InvalidMagic(format!(
                "Expected magic bytes {:02x?}, got {:02x?}",
                OBJECT_MAGIC, magic,
            )));
        }
        res.header.magic.copy_from_slice(magic);

        let (version_bytes, rest) = chop(rest, 4)?;
        res.header.version = u32::from_le_bytes(version_bytes.try_into().unwrap());
        if res.header.version != OBJECT_VERSION {
            return Err(ObjectError::UnsupportedVersion(format!(
                "Expected version {}, got {}",
                OBJECT_VERSION, res.header.version
            )));
        }

        let (flags_bytes, rest) = chop(rest, 8)?;
        res.header.flags = u64::from_le_bytes(flags_bytes.try_into().unwrap());

        let (chunk_count_bytes, rest) = chop(rest, 4)?;
        let chunk_count = u32::from_le_bytes(chunk_count_bytes.try_into().unwrap());

        let (chunk_offset_bytes, _) = chop(rest, 8)?;
        let chunk_offset = u64::from_le_bytes(chunk_offset_bytes.try_into().unwrap());

        if chunk_offset as usize > data.len() {
            return Err(ObjectError::InsufficientData(
                "Chunk offset is beyond the end of the data".to_string(),
            ));
        }

        let mut chunks_data = &data[chunk_offset as usize..];

        for _ in 0..chunk_count {
            chunks_data = align_slice(data, chunks_data, 8)?;

            let (chunk_type_bytes, rest) = chop(chunks_data, 4)?;
            let chunk_type = u32::from_le_bytes(chunk_type_bytes.try_into().unwrap());

            let chunk_kind = ChunkKind::from_u32(chunk_type).ok_or(
                ObjectError::InvalidChunkKind(format!("Invalid chunk type: {:02x?}", chunk_type)),
            )?;

            let (data_len_bytes, rest) = chop(rest, 4)?;
            let data_len = u32::from_le_bytes(data_len_bytes.try_into().unwrap()) as usize;

            if data_len > rest.len() {
                return Err(ObjectError::InsufficientData(
                    "Chunk data length is greater than remaining data".to_string(),
                ));
            }

            let (chunk_data, rest) = chop(rest, data_len)?;
            let chunk_data = align_slice(data, chunk_data, 8)?;

            match chunk_kind {
                ChunkKind::Metadata => {
                    let mut metadata_data = chunk_data;

                    while !metadata_data.is_empty() {
                        let (key, rest) = chop_stringz(metadata_data)?;
                        let key = String::from_utf8(key.to_vec()).map_err(|_| {
                            ObjectError::InvalidMetadataKey(format!(
                                "Invalid metadata key: {:?}",
                                key
                            ))
                        })?;

                        metadata_data = align_slice(data, rest, 8)?;

                        let (length_bytes, rest) = chop(metadata_data, 4)?;
                        let length = u32::from_le_bytes(length_bytes.try_into().unwrap()) as usize;

                        if length > rest.len() {
                            return Err(ObjectError::InsufficientData(
                                "Metadata value length is greater than remaining data".to_string(),
                            ));
                        }

                        let (value, rest) = chop(rest, length)?;

                        res.metadata.push((key, value.to_vec()));

                        // try aligning to next, if it fails, return an empty slice
                        // breaking the loop
                        metadata_data = match align_slice(data, rest, 8) {
                            Ok(data) => data,
                            Err(_) => &[],
                        };
                    }
                }
                ChunkKind::Symbols => {
                    let mut symbols_data = chunk_data;

                    while !symbols_data.is_empty() {
                        let (symbol_kind_byte, rest) = chop(symbols_data, 1)?;
                        let symbol_kind = SymbolKind::from_u8(symbol_kind_byte[0]).ok_or(
                            ObjectError::InvalidSymbolKind(format!(
                                "Invalid symbol kind byte: {:02x?}",
                                symbol_kind_byte
                            )),
                        )?;

                        let (symbol_linkage_byte, rest) = chop(rest, 1)?;
                        let symbol_linkage = SymbolLinkage::from_u8(symbol_linkage_byte[0]).ok_or(
                            ObjectError::InvalidSymbolLinkage(format!(
                                "Invalid symbol linkage byte: {:02x?}",
                                symbol_linkage_byte
                            )),
                        )?;

                        let rest = align_slice(data, rest, 8)?;

                        let (offset_bytes, rest) = chop(rest, 8)?;
                        let offset = u64::from_le_bytes(offset_bytes.try_into().unwrap());

                        let (section_name, rest) = chop_stringz(rest)?;
                        let section_name = if !section_name.is_empty() {
                            Some(String::from_utf8(section_name.to_vec()).map_err(|_| {
                                ObjectError::InvalidSectionName(format!(
                                    "Invalid section name in symbol: {:?}",
                                    section_name
                                ))
                            })?)
                        } else {
                            None
                        };

                        let (symbol_name, rest) = chop_stringz(rest)?;
                        let symbol_name = if !symbol_name.is_empty() {
                            Some(String::from_utf8(symbol_name.to_vec()).map_err(|_| {
                                ObjectError::InvalidSymbolName(format!(
                                    "Invalid symbol name in symbol: {:?}",
                                    symbol_name
                                ))
                            })?)
                        } else {
                            None
                        };

                        res.symbols.push(Symbol {
                            symbol_kind,
                            linkage: symbol_linkage,
                            offset,
                            section_name,
                            name: symbol_name,
                        });

                        // try aligning to next, if it fails, return an empty slice
                        // breaking the loop
                        symbols_data = match align_slice(data, rest, 8) {
                            Ok(data) => data,
                            Err(_) => &[],
                        };
                    }
                }
                ChunkKind::Relocations => {
                    let mut relocation_data = chunk_data;

                    while !relocation_data.is_empty() {
                        let (relocation_kind_byte, rest) = chop(relocation_data, 1)?;
                        let relocation_kind = RelocationKind::from_u8(relocation_kind_byte[0])
                            .ok_or(ObjectError::InvalidRelocationKind(format!(
                                "Invalid relocation kind byte: {:02x?}",
                                relocation_kind_byte
                            )))?;

                        let (symbol_name, rest) = chop_stringz(rest)?;
                        let symbol_name =
                            String::from_utf8(symbol_name.to_vec()).map_err(|_| {
                                ObjectError::InvalidSymbolName(format!(
                                    "Invalid symbol name in relocation: {:?}",
                                    symbol_name
                                ))
                            })?;

                        let rest = align_slice(data, rest, 8)?;

                        let (offset_bytes, rest) = chop(rest, 8)?;
                        let offset = u64::from_le_bytes(offset_bytes.try_into().unwrap());

                        let (addend_bytes, rest) = chop(rest, 8)?;
                        let addend = i64::from_le_bytes(addend_bytes.try_into().unwrap());

                        res.relocations.push(Relocation {
                            relocation_kind,
                            symbol: symbol_name,
                            offset,
                            addend,
                        });

                        // try aligning to next, if it fails, return an empty slice
                        // breaking the loop
                        relocation_data = match align_slice(data, rest, 8) {
                            Ok(data) => data,
                            Err(_) => &[],
                        };
                    }
                }
                ChunkKind::Section => {
                    let mut section_data = chunk_data;

                    while !section_data.is_empty() {
                        let (section_kind_bytes, rest) = chop(section_data, 4)?;
                        let section_kind = SectionKind::from_u8(section_kind_bytes[0]).ok_or(
                            ObjectError::InvalidSectionKind(format!(
                                "Invalid section kind byte: {:02x?}",
                                section_kind_bytes
                            )),
                        )?;

                        let (address_bytes, rest) = chop(rest, 2)?;
                        let address = u16::from_le_bytes(address_bytes.try_into().unwrap());

                        let rest = align_slice(data, rest, 4)?;

                        let (section_name, rest) = chop_stringz(rest)?;
                        let section_name =
                            String::from_utf8(section_name.to_vec()).map_err(|_| {
                                ObjectError::InvalidSectionName(format!(
                                    "Invalid section name in section: {:?}",
                                    section_name
                                ))
                            })?;

                        let rest = align_slice(data, rest, 8)?;

                        let (data_size_bytes, rest) = chop(rest, 8)?;
                        let data_size =
                            u64::from_le_bytes(data_size_bytes.try_into().unwrap()) as usize;

                        if data_size > rest.len() {
                            return Err(ObjectError::InsufficientData(
                                "Section data size is greater than remaining data".to_string(),
                            ));
                        }

                        let (data, rest) = chop(rest, data_size)?;

                        res.sections.push(Section {
                            section_kind,
                            address,
                            name: section_name,
                            data: data.to_vec(),
                        });

                        // try aligning to next, if it fails, return an empty slice
                        // breaking the loop
                        section_data = match align_slice(data, rest, 8) {
                            Ok(data) => data,
                            Err(_) => &[],
                        };
                    }
                }
            }

            chunks_data = rest;
        }

        Ok(res)
    }
}
