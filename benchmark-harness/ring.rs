//! Single-threaded bounded FIFO fixture, not a kernel queue or concurrent channel.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ring<const N: usize> {
    values: [u64; N],
    head: usize,
    length: usize,
}

impl<const N: usize> Ring<N> {
    pub fn new() -> Self {
        assert!(N > 0, "a ring needs nonzero capacity");
        Self {
            values: [0; N],
            head: 0,
            length: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn push(&mut self, value: u64) -> Result<(), u64> {
        if self.length == N {
            return Err(value);
        }
        self.values[(self.head + self.length) % N] = value;
        self.length += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<u64> {
        if self.length == 0 {
            return None;
        }
        let value = self.values[self.head];
        self.head = (self.head + 1) % N;
        self.length -= 1;
        Some(value)
    }
}
