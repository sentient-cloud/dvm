use std::ops::Add;

pub mod compiler;
pub mod linker;
pub mod object;
pub mod parser;

pub struct SpanUsage<T>
where
    T: Copy + Add + Ord,
{
    // entries are stored as (start, end) pairs (half-open intervals)
    entries: Vec<(T, T)>,

    // min and max define the valid range for entries
    min: T,
    max: T,
}

impl<T> SpanUsage<T>
where
    T: Copy + Add + Ord,
{
    pub fn new(min: T, max: T) -> Self {
        SpanUsage {
            entries: Vec::new(),
            min,
            max,
        }
    }

    pub fn insert(&mut self, start: T, end: T) -> bool {
        if start < self.min || end > self.max || start >= end {
            return false;
        }

        if self.entries.is_empty() {
            self.entries.push((start, end));
            return true;
        }

        let pos = match self.entries.binary_search_by(|&(s, _)| s.cmp(&start)) {
            Ok(pos) => pos,
            Err(pos) => pos,
        };

        if pos > 0 && self.entries[pos - 1].1 > start {
            return false;
        }

        if pos < self.entries.len() && self.entries[pos].0 < end {
            return false;
        }

        self.entries.insert(pos, (start, end));

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_usage_insert() {
        let mut usage = SpanUsage::new(0, 100);
        assert!(usage.insert(10, 20));
        assert!(usage.insert(20, 30)); // adjacent to (20, 30)
        assert!(usage.insert(30, 40));

        assert!(!usage.insert(5, 15)); // overlaps with (10, 20)
        assert!(!usage.insert(15, 25)); // overlaps with (10, 20)
        assert!(!usage.insert(90, 110)); // out of bounds
    }
}
