//! Shannon entropy over byte frequencies. High entropy (close to 8 bits per
//! byte) is the signature of compressed, packed or encrypted data — the
//! blobs a source review can never read.

/// Streaming byte-frequency counter; feed chunks, then ask for entropy.
pub struct Counter {
    counts: [u64; 256],
    total: u64,
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl Counter {
    pub fn new() -> Self {
        Counter {
            counts: [0u64; 256],
            total: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.counts[b as usize] += 1;
        }
        self.total += data.len() as u64;
    }

    /// Shannon entropy in bits per byte, in `[0.0, 8.0]`. An empty stream
    /// has entropy 0 by convention.
    pub fn bits_per_byte(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        let mut h = 0.0f64;
        for &c in &self.counts {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total;
            h -= p * p.log2();
        }
        h
    }

    pub fn bytes_seen(&self) -> u64 {
        self.total
    }
}

/// One-shot entropy of an in-memory buffer.
pub fn bits_per_byte(data: &[u8]) -> f64 {
    let mut c = Counter::new();
    c.update(data);
    c.bits_per_byte()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(bits_per_byte(b""), 0.0);
    }

    #[test]
    fn constant_byte_is_zero() {
        // A run of one symbol carries no information at all.
        assert_eq!(bits_per_byte(&[0x41u8; 4096]), 0.0);
    }

    #[test]
    fn two_equiprobable_symbols_are_one_bit() {
        let data: Vec<u8> = (0..1024)
            .map(|i| if i % 2 == 0 { 0u8 } else { 255u8 })
            .collect();
        let h = bits_per_byte(&data);
        assert!((h - 1.0).abs() < 1e-9, "expected 1.0 bit, got {h}");
    }

    #[test]
    fn uniform_bytes_are_exactly_eight_bits_and_never_more() {
        // Every byte value exactly four times: the theoretical maximum.
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let h = bits_per_byte(&data);
        assert!((h - 8.0).abs() < 1e-9, "expected 8.0 bits, got {h}");
        // Any distribution must stay at or below the maximum.
        let noisy: Vec<u8> = (0..100_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        assert!(bits_per_byte(&noisy) <= 8.0);
    }

    #[test]
    fn english_like_text_is_mid_range() {
        // Plain prose sits far below the 7.5 default threshold; this guards
        // against a broken formula that flags every README as a blob.
        let text = b"the quick brown fox jumps over the lazy dog, and does so again and again";
        let h = bits_per_byte(text);
        assert!(h > 3.0 && h < 5.0, "prose entropy out of range: {h}");
    }

    #[test]
    fn streaming_equals_one_shot() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut c = Counter::new();
        for chunk in data.chunks(7) {
            c.update(chunk);
        }
        assert_eq!(c.bits_per_byte(), bits_per_byte(&data));
        assert_eq!(c.bytes_seen(), data.len() as u64);
    }
}
