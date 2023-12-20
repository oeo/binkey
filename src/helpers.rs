// helpers.rs
use log::{error};
use std::io::{self, Write};
use rand::Rng;

use base64::{Engine as _, engine::{general_purpose}};

pub fn b64_encode<T: AsRef<[u8]>>(data: T) -> String {
    general_purpose::STANDARD.encode(data)
}

/*
pub fn b64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(input)
}
*/

pub fn random_letters(length: Option<usize>) -> String {
    let length = length.unwrap_or(10);
    let mut rng = rand::thread_rng();
    let alphanumeric_chars: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let random_chars: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..alphanumeric_chars.len());
            alphanumeric_chars[idx] as char
        })
        .collect();
    random_chars
}

pub fn prompt_for_password(require_confirmation: bool) -> String {
    let mut password = String::new();

    print!("Password: ");

    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut password).unwrap();
    let password_trimmed = password.trim();

    if password_trimmed.is_empty() {
        error!("Password cannot be blank.");
        std::process::exit(1);
    }

    if require_confirmation {
        let mut confirm_password = String::new();
        print!("Password (confirm): ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut confirm_password).unwrap();
        let confirm_password_trimmed = confirm_password.trim();

        if password_trimmed != confirm_password_trimmed {
            error!("Passwords did not match.");
            std::process::exit(1);
        }
    }

    password_trimmed.to_string()
}

/*
pub fn confirm_replacement(assume_yes: bool) -> bool {
    let mut input = String::new();

    if assume_yes {
        print!("Confirm file replace [Y/n]: ");
    }else{
        print!("Confirm file replace [y/N]: ");
    }

    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    match input {
        "y" | "Y" => true,
        "n" | "N" => false,
        _ => {
            if assume_yes {
                return true
            }else{
                return false
            }
        }
    }
}
*/

