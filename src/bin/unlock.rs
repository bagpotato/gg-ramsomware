use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256, Block};
use sha2::Sha256;
use walkdir::WalkDir;

const PASS: &str = "3Do4p9h+?U|/OWU`4qZG£(FA7";
const SALT: &[u8] = b"u're fucked";
const MAGIC: &[u8; 3] = b"GGs";

fn wide_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s.starts_with("\\\\?\\") {
        p.to_path_buf()
    } else {
        PathBuf::from(format!("\\\\?\\{s}"))
    }
}

fn clear_readonly(p: &Path) {
    if let Ok(md) = fs::metadata(p) {
        let mut perm = md.permissions();
        if perm.readonly() {
            perm.set_readonly(false);
            let _ = fs::set_permissions(p, perm);
        }
    }
}

fn decrypt_file(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    clear_readonly(path);

    let name = path.to_string_lossy().to_string();
    let orig = PathBuf::from(name.trim_end_matches(".locked"));

    let mut fin = File::open(path)?;
    let mut hdr = [0u8; 19];
    fin.read_exact(&mut hdr)?;
    if &hdr[..3] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }
    let mut prev: [u8; 16] = hdr[3..19].try_into().unwrap();

    let cipher = Aes256::new(key.into());
    let mut fout = OpenOptions::new().write(true).create(true).truncate(true).open(&orig)?;

    let mut buf = vec![0u8; 1 << 20];
    let mut pending: Vec<u8> = Vec::new();
    let mut pending_out: Option<[u8; 16]> = None;

    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..n]);

        let full = (pending.len() / 16) * 16;
        for chunk in pending[..full].chunks_exact(16) {
            let ct: [u8; 16] = chunk.try_into().unwrap();
            let mut blk = [0u8; 16];
            blk.copy_from_slice(chunk);
            cipher.decrypt_block(Block::from_mut_slice(&mut blk));
            for (a, b) in blk.iter_mut().zip(prev.iter()) {
                *a ^= *b;
            }
            prev = ct;
            if let Some(p) = pending_out.take() {
                fout.write_all(&p)?;
            }
            pending_out = Some(blk);
        }
        pending.drain(..full);
    }

    // deshacer PKCS7 del ultimo bloque
    if let Some(mut last) = pending_out {
        let pad = *last.last().unwrap_or(&0) as usize;
        if pad >= 1 && pad <= 16 {
            for b in last.iter_mut().rev().take(pad) {
                *b = 0;
            }
            fout.write_all(&last[..16 - pad])?;
        } else {
            fout.write_all(&last)?;
        }
    }

    fout.flush()?;
    drop(fout);
    drop(fin);
    fs::remove_file(path)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut roots: Vec<PathBuf> = Vec::new();
    for a in &args {
        if !a.starts_with("--") {
            roots.push(wide_path(Path::new(a)));
        }
    }
    if roots.is_empty() {
        for letter in b'A'..=b'Z' {
            let p = format!("{}:\\", letter as char);
            if Path::new(&p).exists() {
                roots.push(wide_path(Path::new(&p)));
            }
        }
    }

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(PASS.as_bytes(), SALT, 200_000, &mut key);

    let mut ok = 0u64;
    let mut bad = 0u64;
    for root in &roots {
        for e in WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            if !e.file_type().is_file() {
                continue;
            }
            let p = e.path();
            if p.extension().map(|x| x == "locked").unwrap_or(false) {
                match decrypt_file(p, &key) {
                    Ok(_) => ok += 1,
                    Err(_) => bad += 1,
                }
            }
        }
    }
    println!("Restored: {ok}  Errors: {bad}");
}