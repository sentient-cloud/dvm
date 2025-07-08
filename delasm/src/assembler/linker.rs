use std::collections::HashMap;

use crate::assembler::object::Object;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkerError {
    DuplicateSymbol(String),
    SymbolNotFound(String),
    InvalidRelocation(String),
    OverlappingSections(String),
    SectionNotFound(String),
}

pub struct Linker {
    pub objects: Vec<Object>,

    // Lookup table for symbols in each object, (section_name, symbol_name) -> index
    pub object_symbol_luts: Vec<HashMap<(String, String), usize>>,
}

impl Linker {
    pub fn new() -> Self {
        Linker {
            objects: Vec::new(),
            object_symbol_luts: Vec::new(),
        }
    }

    pub fn add_object(&mut self, object: Object) -> Result<(), LinkerError> {
        let mut symbol_lut = HashMap::new();

        for (index, symbol) in object.symbols.iter().enumerate() {
            let mut key = ("".to_string(), "".to_string());

            if let Some(section_name) = &symbol.section_name {
                key.0 = section_name.clone();
            }

            if let Some(symbol_name) = &symbol.name {
                key.1 = symbol_name.clone();
            }

            if symbol_lut.contains_key(&key) {
                return Err(LinkerError::DuplicateSymbol(format!(
                    "Duplicate symbol in object, found multiple symbol '{}' in section '{}'",
                    key.1, key.0
                )));
            }

            for other_luts in self.object_symbol_luts.iter() {
                if let Some(&existing_index) = other_luts.get(&key) {
                    return Err(LinkerError::DuplicateSymbol(format!(
                        "Duplicate symbol '{}' in section '{}', already exists in object at index {}",
                        key.1, key.0, existing_index
                    )));
                }
            }

            symbol_lut.insert(key, index);
        }

        self.objects.push(object);
        self.object_symbol_luts.push(symbol_lut);

        Ok(())
    }

    pub fn iter_objects<'a>(
        &'a self,
        parent_object: Option<&'a Object>,
    ) -> impl Iterator<Item = (usize, &'a Object)> {
        let parent_addr = parent_object.map_or(std::ptr::null(), |obj| obj as *const _);

        // best iterator ever
        std::iter::once(
            self.objects
                .iter()
                .enumerate()
                .find(|(_, obj)| *obj as *const _ == parent_addr),
        )
        .flatten()
        .chain(
            self.objects
                .iter()
                .enumerate()
                .filter(move |(_, obj)| *obj as *const _ != parent_addr),
        )
    }

    /// Locates a symbol, returns symbol index in object
    ///
    /// Both `section_name` and `symbol_name` can be empty strings.
    pub fn locate_symbol_in_object(
        &self,
        section_name: &str,
        mut symbol_name: &str,
        object_index: usize,
        allow_internal: bool,
    ) -> Option<usize> {
        let object = self.objects.get(object_index)?;
        let symbol_lut = self.object_symbol_luts.get(object_index)?;

        let mut symbol_name_tries = vec![symbol_name.to_string()];

        // strip off section prefix
        if symbol_name.contains('$') {
            (_, symbol_name) = symbol_name.split_once('$').unwrap();
            symbol_name_tries.push(symbol_name.to_string());
        }

        // strip off parent label prefix
        if symbol_name.contains('.') {
            (_, symbol_name) = symbol_name.split_once('.').unwrap();
            symbol_name_tries.push(symbol_name.to_string());
        }

        for name in symbol_name_tries {
            let key = (section_name.to_string(), name.clone());

            if let Some(&index) = symbol_lut.get(&key) {
                if allow_internal && object.symbols[index].linkage.is_internal() {
                    return Some(index);
                } else if object.symbols[index].linkage.is_export() {
                    return Some(index);
                }
            }
        }

        None
    }

    /// Locates a symbol in all objects, returns (object_index, symbol index)
    pub fn locate_symbol<'a>(
        &'a self,
        section_name: &str,
        symbol_name: &str,
        parent_object: Option<&'a Object>,
    ) -> Option<(usize, usize)> {
        let mut allow_parent = parent_object.is_some();

        for (object_index, _) in self.iter_objects(parent_object) {
            if let Some(index) =
                self.locate_symbol_in_object(section_name, symbol_name, object_index, allow_parent)
            {
                return Some((object_index, index));
            }

            allow_parent = false;
        }

        None
    }

    pub fn link_static(&self) -> Result<Object, Vec<LinkerError>> {
        let mut linked_object = Object::new();
        let mut errors = Vec::new();

        for (object_index, object) in self.objects.iter().enumerate() {
            for reloc in object.relocations.iter() {
                if let Some((in_object_index, in_object)) =
                    self.locate_symbol(&reloc.to_section, &reloc.to_symbol, Some(object))
                {
                }
            }
        }

        if errors.len() > 0 {
            return Err(errors);
        }

        Ok(linked_object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::object;

    #[test]
    fn linker_add_object() {
        let mut linker = Linker::new();
        let object = Object::new();

        assert!(linker.add_object(object).is_ok());
        assert_eq!(linker.objects.len(), 1);
    }

    #[test]
    fn linker_duplicate_symbol_in_same_object() {
        let mut linker = Linker::new();
        let mut object = Object::new();

        for _ in 0..2 {
            object.symbols.push(object::Symbol {
                name: Some("test".to_string()),
                section_name: Some("section".to_string()),
                kind: object::SymbolKind::Code,
                linkage: object::SymbolLinkage::Export,
                offset: 0,
            });
        }

        assert!(linker.add_object(object).is_err());
    }

    #[test]
    fn linker_duplicate_symbol_in_different_object() {
        let mut linker = Linker::new();
        let mut object = Object::new();

        object.symbols.push(object::Symbol {
            name: Some("test".to_string()),
            section_name: Some("section".to_string()),
            kind: object::SymbolKind::Code,
            linkage: object::SymbolLinkage::Export,
            offset: 0,
        });

        assert!(linker.add_object(object.clone()).is_ok());
        assert!(linker.add_object(object).is_err());
    }

    #[test]
    fn linker_object_iter_with_parent() {
        let mut linker = Linker::new();

        linker.add_object(Object::new()).unwrap();
        linker.add_object(Object::new()).unwrap();
        linker.add_object(Object::new()).unwrap();
        linker.add_object(Object::new()).unwrap();

        let parent = &linker.objects[1];
        let mut iter = linker.iter_objects(Some(parent));

        assert_eq!(iter.next().unwrap().0, 1);
        assert_eq!(iter.next().unwrap().0, 0);
        assert_eq!(iter.next().unwrap().0, 2);
        assert_eq!(iter.next().unwrap().0, 3);
        assert!(iter.next().is_none());
    }

    #[test]
    fn linker_locate_symbol_internal() {
        let mut linker = Linker::new();
        let mut object = Object::new();

        object.symbols.push(object::Symbol {
            name: Some("test".to_string()),
            section_name: Some("section".to_string()),
            kind: object::SymbolKind::Code,
            linkage: object::SymbolLinkage::Internal,
            offset: 0,
        });

        assert!(linker.add_object(object).is_ok());

        assert_eq!(
            linker.locate_symbol_in_object("section", "test", 0, true),
            Some(0)
        );

        assert_eq!(
            linker.locate_symbol_in_object("section", "test", 0, false),
            None
        );
    }

    #[test]
    fn linker_locate_symbol_export() {
        let mut linker = Linker::new();
        let mut object = Object::new();

        object.symbols.push(object::Symbol {
            name: Some("test".to_string()),
            section_name: Some("section".to_string()),
            kind: object::SymbolKind::Code,
            linkage: object::SymbolLinkage::Export,
            offset: 0,
        });

        assert!(linker.add_object(object).is_ok());

        assert_eq!(
            linker.locate_symbol_in_object("section", "test", 0, true),
            Some(0)
        );

        assert_eq!(
            linker.locate_symbol_in_object("section", "test", 0, false),
            Some(0)
        );
    }

    #[test]
    fn linker_locate_symbol_multiple_objects() {
        let mut linker = Linker::new();

        let mut object1 = Object::new();
        object1.symbols.push(object::Symbol {
            name: Some("test".to_string()),
            section_name: Some("section".to_string()),
            kind: object::SymbolKind::Code,
            linkage: object::SymbolLinkage::Internal,
            offset: 0,
        });

        let mut object2 = Object::new();
        object2.symbols.push(object::Symbol {
            name: Some("test2".to_string()),
            section_name: Some("section".to_string()),
            kind: object::SymbolKind::Code,
            linkage: object::SymbolLinkage::Export,
            offset: 0,
        });

        assert!(linker.add_object(object1).is_ok());
        assert!(linker.add_object(object2).is_ok());

        // find an internal symbol
        assert_eq!(
            linker.locate_symbol("section", "test", Some(&linker.objects[0])),
            Some((0, 0))
        );

        // find an export symbol
        assert_eq!(
            linker.locate_symbol("section", "test2", Some(&linker.objects[0])),
            Some((1, 0))
        );
    }
}
