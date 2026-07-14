//! blobfind — inventories native binaries, shared libraries and
//! high-entropy blobs hiding inside dependency trees, with provenance
//! hints. Fully offline; reads files, never writes outside `-o`.

pub mod baseline;
pub mod cli;
pub mod entropy;
pub mod inventory;
pub mod json;
pub mod provenance;
pub mod report;
pub mod sha256;
pub mod sniff;
pub mod util;
pub mod walk;
