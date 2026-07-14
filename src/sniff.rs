//! Magic-byte format detection: ELF, Mach-O (thin and fat), PE/COFF,
//! WebAssembly, Java class files, static libraries and the archive formats
//! that most often smuggle prebuilt binaries into dependency trees.
//! Everything is decided from the first 512 bytes of the file.

/// How many leading bytes [`detect`] needs to see.
pub const HEADER_LEN: usize = 512;

/// A recognized file format, with whatever the header reveals.
#[derive(Debug, Clone, PartialEq)]
pub enum Format {
    Elf {
        bits: u8,
        little_endian: bool,
        etype: ElfType,
        machine: String,
    },
    MachO {
        bits: u8,
        cpu: String,
        filetype: MachType,
    },
    MachOFat {
        arches: u32,
    },
    Pe {
        machine: String,
        dll: bool,
    },
    Wasm {
        version: u32,
    },
    JavaClass {
        major: u16,
    },
    /// `!<arch>` static library / ar archive (`.a`, `.lib`).
    ArArchive,
    Zip,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Tar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    Relocatable,
    Executable,
    SharedObject,
    Core,
    Other(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachType {
    Object,
    Executable,
    Dylib,
    Bundle,
    Other(u32),
}

impl Format {
    /// Native executable code (as opposed to an archive that may contain it).
    pub fn is_native(&self) -> bool {
        matches!(
            self,
            Format::Elf { .. }
                | Format::MachO { .. }
                | Format::MachOFat { .. }
                | Format::Pe { .. }
                | Format::Wasm { .. }
                | Format::JavaClass { .. }
                | Format::ArArchive
        )
    }

    /// Human-readable one-line description, e.g. `ELF shared object`.
    pub fn describe(&self) -> String {
        match self {
            Format::Elf { etype, .. } => match etype {
                ElfType::Relocatable => "ELF relocatable object".into(),
                ElfType::Executable => "ELF executable".into(),
                ElfType::SharedObject => "ELF shared object".into(),
                ElfType::Core => "ELF core dump".into(),
                ElfType::Other(t) => format!("ELF (type {t})"),
            },
            Format::MachO { filetype, .. } => match filetype {
                MachType::Object => "Mach-O object".into(),
                MachType::Executable => "Mach-O executable".into(),
                MachType::Dylib => "Mach-O dylib".into(),
                MachType::Bundle => "Mach-O bundle".into(),
                MachType::Other(t) => format!("Mach-O (filetype {t})"),
            },
            Format::MachOFat { arches } => format!("Mach-O universal binary ({arches} arches)"),
            Format::Pe { dll: true, .. } => "PE DLL".into(),
            Format::Pe { dll: false, .. } => "PE executable".into(),
            Format::Wasm { version } => format!("WebAssembly module (v{version})"),
            Format::JavaClass { major } => format!("Java class file (major {major})"),
            Format::ArArchive => "static library (ar archive)".into(),
            Format::Zip => "zip archive".into(),
            Format::Gzip => "gzip data".into(),
            Format::Xz => "xz data".into(),
            Format::Zstd => "zstd data".into(),
            Format::Bzip2 => "bzip2 data".into(),
            Format::Tar => "tar archive".into(),
        }
    }

    /// Architecture string when the header names one.
    pub fn arch(&self) -> Option<String> {
        match self {
            Format::Elf { machine, bits, .. } => Some(format!("{machine} ({bits}-bit)")),
            Format::MachO { cpu, .. } => Some(cpu.clone()),
            Format::MachOFat { .. } => Some("multi-arch".into()),
            Format::Pe { machine, .. } => Some(machine.clone()),
            _ => None,
        }
    }
}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u32be(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn elf_machine_name(m: u16) -> String {
    match m {
        3 => "x86".into(),
        8 => "MIPS".into(),
        20 => "PowerPC".into(),
        21 => "PowerPC64".into(),
        22 => "S390".into(),
        40 => "ARM".into(),
        62 => "x86-64".into(),
        183 => "AArch64".into(),
        243 => "RISC-V".into(),
        other => format!("EM_{other}"),
    }
}

fn macho_cpu_name(cpu: u32) -> String {
    match cpu {
        7 => "x86".into(),
        0x0100_0007 => "x86-64".into(),
        12 => "ARM".into(),
        0x0100_000c => "ARM64".into(),
        18 => "PowerPC".into(),
        other => format!("cputype {other}"),
    }
}

fn pe_machine_name(m: u16) -> String {
    match m {
        0x014c => "x86".into(),
        0x8664 => "x86-64".into(),
        0x01c0 => "ARM".into(),
        0xaa64 => "ARM64".into(),
        other => format!("machine 0x{other:04x}"),
    }
}

fn detect_elf(b: &[u8]) -> Option<Format> {
    if b.len() < 0x14 || &b[..4] != b"\x7fELF" {
        return None;
    }
    let bits = match b[4] {
        1 => 32,
        2 => 64,
        _ => return None,
    };
    let little_endian = match b[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let read16 = |off: usize| -> u16 {
        if little_endian {
            u16le(b, off)
        } else {
            u16::from_be_bytes([b[off], b[off + 1]])
        }
    };
    let etype = match read16(0x10) {
        1 => ElfType::Relocatable,
        2 => ElfType::Executable,
        3 => ElfType::SharedObject,
        4 => ElfType::Core,
        t => ElfType::Other(t),
    };
    Some(Format::Elf {
        bits,
        little_endian,
        etype,
        machine: elf_machine_name(read16(0x12)),
    })
}

fn detect_macho(b: &[u8]) -> Option<Format> {
    if b.len() < 16 {
        return None;
    }
    let magic = u32be(b, 0);
    // Thin Mach-O, both endiannesses as they appear on disk.
    let (bits, swapped) = match magic {
        0xfeed_face => (32, false),
        0xfeed_facf => (64, false),
        0xcefa_edfe => (32, true),
        0xcffa_edfe => (64, true),
        _ => return None,
    };
    let read32 = |off: usize| -> u32 {
        if swapped {
            u32le(b, off)
        } else {
            u32be(b, off)
        }
    };
    let cpu = macho_cpu_name(read32(4));
    let filetype = match read32(12) {
        1 => MachType::Object,
        2 => MachType::Executable,
        6 => MachType::Dylib,
        8 => MachType::Bundle,
        t => MachType::Other(t),
    };
    Some(Format::MachO {
        bits,
        cpu,
        filetype,
    })
}

/// `0xCAFEBABE` is shared by fat Mach-O and Java class files. The next four
/// bytes disambiguate: a fat header stores the architecture count (tiny; real
/// binaries have < 45), a class file stores minor/major version where major
/// is >= 45 (JDK 1.0) — so the two value ranges never overlap.
fn detect_cafebabe(b: &[u8]) -> Option<Format> {
    if b.len() < 8 || u32be(b, 0) != 0xcafe_babe {
        return None;
    }
    let next = u32be(b, 4);
    if next < 45 {
        Some(Format::MachOFat { arches: next })
    } else {
        Some(Format::JavaClass {
            major: (next & 0xffff) as u16,
        })
    }
}

fn detect_pe(b: &[u8]) -> Option<Format> {
    if b.len() < 0x40 || &b[..2] != b"MZ" {
        return None;
    }
    let pe_off = u32le(b, 0x3c) as usize;
    // Only trust headers that fit in the sniff window; a plain DOS stub or a
    // truncated read is reported as unrecognized rather than guessed at.
    if pe_off + 24 > b.len() || &b[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    let machine = pe_machine_name(u16le(b, pe_off + 4));
    let characteristics = u16le(b, pe_off + 22);
    Some(Format::Pe {
        machine,
        dll: characteristics & 0x2000 != 0,
    })
}

/// Detect a format from the first bytes of a file (`header`) given the full
/// file length. Returns `None` for anything unrecognized.
pub fn detect(header: &[u8], file_len: u64) -> Option<Format> {
    if let Some(f) = detect_elf(header) {
        return Some(f);
    }
    if let Some(f) = detect_macho(header) {
        return Some(f);
    }
    if let Some(f) = detect_cafebabe(header) {
        return Some(f);
    }
    if let Some(f) = detect_pe(header) {
        return Some(f);
    }
    if header.len() >= 8 && &header[..4] == b"\0asm" {
        return Some(Format::Wasm {
            version: u32le(header, 4),
        });
    }
    if header.len() >= 8 && &header[..8] == b"!<arch>\n" {
        return Some(Format::ArArchive);
    }
    if header.len() >= 4 && &header[..4] == b"PK\x03\x04" {
        return Some(Format::Zip);
    }
    if header.len() >= 2 && &header[..2] == b"\x1f\x8b" {
        return Some(Format::Gzip);
    }
    if header.len() >= 6 && &header[..6] == b"\xfd7zXZ\0" {
        return Some(Format::Xz);
    }
    if header.len() >= 4 && &header[..4] == b"\x28\xb5\x2f\xfd" {
        return Some(Format::Zstd);
    }
    if header.len() >= 4 && &header[..3] == b"BZh" && header[3].is_ascii_digit() {
        return Some(Format::Bzip2);
    }
    // tar has no leading magic; "ustar" sits at offset 257 and tar files are
    // at least one 512-byte block long.
    if header.len() >= 262 && &header[257..262] == b"ustar" && file_len >= 512 {
        return Some(Format::Tar);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but well-formed ELF header for the given class/endian/type.
    pub fn elf_bytes(bits: u8, little: bool, etype: u16, machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = if bits == 64 { 2 } else { 1 };
        b[5] = if little { 1 } else { 2 };
        b[6] = 1; // EV_CURRENT
        let (t, m) = if little {
            (etype.to_le_bytes(), machine.to_le_bytes())
        } else {
            (etype.to_be_bytes(), machine.to_be_bytes())
        };
        b[0x10..0x12].copy_from_slice(&t);
        b[0x12..0x14].copy_from_slice(&m);
        b
    }

    #[test]
    fn elf_shared_object_x86_64_little_endian() {
        let b = elf_bytes(64, true, 3, 62);
        let f = detect(&b, b.len() as u64).expect("must detect ELF");
        assert_eq!(
            f,
            Format::Elf {
                bits: 64,
                little_endian: true,
                etype: ElfType::SharedObject,
                machine: "x86-64".into()
            }
        );
        assert_eq!(f.describe(), "ELF shared object");
        assert_eq!(f.arch().as_deref(), Some("x86-64 (64-bit)"));
        assert!(f.is_native());
    }

    #[test]
    fn elf_big_endian_fields_are_swapped() {
        // s390 binaries are big-endian; the type/machine fields must be read
        // with the declared byte order, not assumed little-endian.
        let b = elf_bytes(64, false, 2, 22);
        match detect(&b, 64).unwrap() {
            Format::Elf {
                little_endian,
                etype,
                machine,
                ..
            } => {
                assert!(!little_endian);
                assert_eq!(etype, ElfType::Executable);
                assert_eq!(machine, "S390");
            }
            other => panic!("wrong format: {other:?}"),
        }
    }

    #[test]
    fn elf_aarch64_and_riscv_names() {
        assert!(matches!(
            detect(&elf_bytes(64, true, 3, 183), 64),
            Some(Format::Elf { machine, .. }) if machine == "AArch64"
        ));
        assert!(matches!(
            detect(&elf_bytes(64, true, 3, 243), 64),
            Some(Format::Elf { machine, .. }) if machine == "RISC-V"
        ));
    }

    fn macho_bytes(magic: u32, cpu: u32, filetype: u32, swapped: bool) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[..4].copy_from_slice(&magic.to_be_bytes());
        if swapped {
            b[4..8].copy_from_slice(&cpu.to_le_bytes());
            b[12..16].copy_from_slice(&filetype.to_le_bytes());
        } else {
            b[4..8].copy_from_slice(&cpu.to_be_bytes());
            b[12..16].copy_from_slice(&filetype.to_be_bytes());
        }
        b
    }

    #[test]
    fn macho_arm64_dylib_as_written_on_apple_silicon() {
        // Little-endian Mach-O appears byte-swapped on disk: cf fa ed fe.
        let b = macho_bytes(0xcffa_edfe, 0x0100_000c, 6, true);
        let f = detect(&b, 32).unwrap();
        assert_eq!(
            f,
            Format::MachO {
                bits: 64,
                cpu: "ARM64".into(),
                filetype: MachType::Dylib
            }
        );
        assert_eq!(f.describe(), "Mach-O dylib");
    }

    #[test]
    fn macho_big_endian_executable() {
        let b = macho_bytes(0xfeed_face, 18, 2, false);
        assert_eq!(
            detect(&b, 32).unwrap(),
            Format::MachO {
                bits: 32,
                cpu: "PowerPC".into(),
                filetype: MachType::Executable
            }
        );
    }

    #[test]
    fn cafebabe_disambiguates_fat_macho_from_java_class() {
        // Same magic, two formats: a fat header's arch count is tiny, while
        // a class file's minor/major version word reads >= 45 (JDK 1.0).
        let mut fat = vec![0u8; 16];
        fat[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes()); // 2 arches
        assert_eq!(detect(&fat, 16).unwrap(), Format::MachOFat { arches: 2 });

        let mut class = vec![0u8; 16];
        class[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        class[6..8].copy_from_slice(&52u16.to_be_bytes()); // Java 8
        assert_eq!(detect(&class, 16).unwrap(), Format::JavaClass { major: 52 });
    }

    fn pe_bytes(machine: u16, characteristics: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        b[0x80 + 22..0x80 + 24].copy_from_slice(&characteristics.to_le_bytes());
        b
    }

    #[test]
    fn pe_dll_vs_exe_via_characteristics_bit() {
        let dll = detect(&pe_bytes(0x8664, 0x2102), 256).unwrap();
        assert_eq!(
            dll,
            Format::Pe {
                machine: "x86-64".into(),
                dll: true
            }
        );
        assert_eq!(dll.describe(), "PE DLL");
        let exe = detect(&pe_bytes(0xaa64, 0x0102), 256).unwrap();
        assert_eq!(
            exe,
            Format::Pe {
                machine: "ARM64".into(),
                dll: false
            }
        );
    }

    #[test]
    fn mz_without_a_valid_pe_header_is_not_a_pe() {
        // A bare DOS stub (or a text file starting with "MZ") must not be
        // reported as a Windows binary…
        let mut b = vec![0u8; 0x100];
        b[..2].copy_from_slice(b"MZ");
        assert_eq!(detect(&b, 256), None);
        // …and a PE offset pointing outside the sniff window is rejected
        // rather than read out of bounds.
        b[0x3c..0x40].copy_from_slice(&0x0004_0000u32.to_le_bytes());
        assert_eq!(detect(&b, 0x100), None);
    }

    #[test]
    fn wasm_module_with_version() {
        assert_eq!(
            detect(b"\0asm\x01\0\0\0", 8).unwrap(),
            Format::Wasm { version: 1 }
        );
    }

    #[test]
    fn ar_archive_magic() {
        assert_eq!(detect(b"!<arch>\nfoo", 512).unwrap(), Format::ArArchive);
        assert!(Format::ArArchive.is_native());
    }

    #[test]
    fn compression_and_tar_magics() {
        assert_eq!(detect(b"PK\x03\x04....", 100).unwrap(), Format::Zip);
        assert_eq!(detect(b"\x1f\x8b\x08....", 100).unwrap(), Format::Gzip);
        assert_eq!(detect(b"\xfd7zXZ\0..", 100).unwrap(), Format::Xz);
        assert_eq!(detect(b"\x28\xb5\x2f\xfd..", 100).unwrap(), Format::Zstd);
        assert_eq!(detect(b"BZh9....", 100).unwrap(), Format::Bzip2);
        assert!(!Format::Zip.is_native());
        // tar has no leading magic: "ustar" at offset 257, min 512 bytes.
        let mut b = vec![0u8; 512];
        b[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect(&b, 512).unwrap(), Format::Tar);
        // A short file with the same bytes cannot be a real tar.
        assert_eq!(detect(&b, 300), None);
    }

    #[test]
    fn plain_text_and_truncated_magics_are_unrecognized() {
        assert_eq!(detect(b"#!/bin/sh\necho hello\n", 21), None);
        assert_eq!(detect(b"\x7fEL", 3), None);
        assert_eq!(detect(b"", 0), None);
    }
}
