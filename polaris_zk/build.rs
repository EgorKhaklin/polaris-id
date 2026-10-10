// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//! Stamps the binary with the source it was built from: the git tree of the prover's sources as
//! they stand in the working copy, uncommitted changes included (`polaris-zk source-tree` prints it).
//! The local gate (scripts/polaris-ship.py, zk_prover_stale) computes the same tree and refuses a
//! prover built from any other source, by content rather than by file times. Outside a git
//! checkout (an image build) the stamp is "unknown", and the gate falls back to file times.
use std::process::Command;

/// The paths the stamp covers; scripts/polaris-ship.py's ZK_SOURCES lists the same four.
const SOURCES: [&str; 4] = ["src", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

fn main() {
    for p in SOURCES {
        println!("cargo:rerun-if-changed={}", p);
    }
    let tree = source_tree().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=POLARIS_ZK_SOURCE_TREE={}", tree);
}

fn source_tree() -> Option<String> {
    let dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out_dir = std::env::var("OUT_DIR").ok()?;
    // A scratch index, so the stamp never touches the checkout's own: start empty, add the four
    // paths as they are on disk, and write the tree under polaris_zk/.
    let index = std::path::Path::new(&out_dir).join("polaris-zk-source-index");
    let _ = std::fs::remove_file(&index);
    let git = |args: &[&str]| -> Option<String> {
        let mut cmd = Command::new("git");
        // None of a hook's GIT_* (they name another repository or index), as the gate drops them.
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(&k);
            }
        }
        let out = cmd
            .args(args)
            .current_dir(&dir)
            .env("GIT_INDEX_FILE", &index)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
    };
    git(&["read-tree", "--empty"])?;
    // The paths that exist, as the gate reads them; none at all is no stamp.
    let present: Vec<&str> = SOURCES
        .iter()
        .copied()
        .filter(|p| std::path::Path::new(&dir).join(p).exists())
        .collect();
    if present.is_empty() {
        return None;
    }
    let mut add = vec!["add", "-A", "--"];
    add.extend(present);
    git(&add)?;
    let tree = git(&["write-tree", "--prefix=polaris_zk/"])?;
    if tree.len() == 40 && tree.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(tree)
    } else {
        None
    }
}
