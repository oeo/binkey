// main.rs
//#![allow(unused_imports)]
//#![allow(unused_must_use)]
//#![allow(dead_code)]

mod helpers;
mod files;

use files::{
    get_file_details, 
    extract_encrypted_data, 
    chmod_x, 
    read_file, 
    write_file, 
    render_delimiter,
};

use getopts::Options;
use magic_crypt::{new_magic_crypt, MagicCryptTrait, MagicCrypt256};

use std::{env, process, fs::File};
use std::io::{self, Write};
use log::{info, warn, error};

fn encrypt(data: &[u8], password: &str) -> io::Result<String> {
    let mcrypt: MagicCrypt256 = new_magic_crypt!(password, 256);
    let encrypted_data = mcrypt.encrypt_bytes_to_base64(&data);
    Ok(encrypted_data)
}

fn decrypt(encrypted_data_base64: &str, password: &str) -> io::Result<Vec<u8>> {
    let mcrypt: MagicCrypt256 = new_magic_crypt!(password, 256);
    mcrypt.decrypt_base64_to_bytes(&encrypted_data_base64)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption error"))
}

fn print_usage_main(opts: &Options) {
    let brief = format!("Usage: binkey file [outfile] [options]");
    print!("{}", opts.usage(&brief));
}

fn print_usage_stub(opts: &Options) {
    let brief = format!("Usage: ./ [options]");
    print!("{}", opts.usage(&brief));
}

fn stub() {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("o", "outfile", "", "");
    opts.optopt("p", "password", "", "");
    // opts.optflag("s", "stdout", "overrides outfile");
    opts.optflag("h", "help", "");

    let matches = opts.parse(&args[1..]).unwrap_or_else(|f| {
        error!("{}", f.to_string());
        process::exit(1);
    });

    if matches.opt_present("h") {
        print_usage_stub(&opts);
        process::exit(0);
    }

    let exe_path = env::current_exe().unwrap();
    let file_details = get_file_details(&exe_path.to_string_lossy()).unwrap();

    if !file_details.has_footer {
        error!("No encrypted data found in the executable");
        process::exit(1);
    }

    let password = matches.opt_str("p").unwrap_or_else(|| helpers::prompt_for_password(false));
    let output_to_stdout = matches.opt_present("s");
    let outfile = matches.opt_str("o").unwrap_or_else(|| exe_path.to_string_lossy().to_string());

    let encrypted_data = extract_encrypted_data(
        &mut File::open(&exe_path).unwrap(), 
        file_details.delimiter_header_pos, 
        file_details.delimiter_footer_pos
    ).unwrap();

    info!("Extracted encrypted data: {} length: {}", encrypted_data, encrypted_data.len());

    match decrypt(&encrypted_data, &password) {
        Ok(decrypted_data) => {
            info!("Decrypted data length: {}", decrypted_data.len());

            if output_to_stdout {
                io::stdout().write_all(&decrypted_data).unwrap();
            } else {
                if let Err(e) = write_file(&outfile, &decrypted_data) {
                    error!("Failed to write to disk: {}. {}", outfile, e);
                    process::exit(1);
                } else {
                    info!("Decrypted data written to disk {}", outfile);
                }
            }
        },
        Err(e) => {
            error!("Failed to decrypt data: {}", e);
            process::exit(1);
        }
    }

    process::exit(0);
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    env_logger::init();

    let __file = env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    let __file = get_file_details(&__file).unwrap();
    // print!("{:#?}", &__file);

    // this is an encrypted binary stub
    if __file.has_footer {
        stub();
        return;
    }

    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    // opts.optopt("f", "file", "", "");
    opts.optopt("o", "outfile", "", "");
    opts.optopt("p", "password", "", "");
    // opts.optflag("s", "stdout", "overrides outfile");
    opts.optflag("h", "help", "");

    let matches = opts.parse(&args[1..]).unwrap_or_else(|f| {
        error!("{}", f.to_string());
        process::exit(1);
    });

    if matches.opt_present("h") || args.len() < 2 {
        print_usage_main(&opts);
        process::exit(0);
    }

    let filename;
    let outfile;
    
    let free_args = &matches.free;
    match free_args.len() {
        0 => {
            error!("File is required");
            process::exit(1);
        }
        1 => {
            filename = free_args[0].clone();
            outfile = matches.opt_str("o").unwrap_or_else(|| helpers::random_letters(None));
        }
        _ => {
            filename = free_args[0].clone();
            outfile = if let Some(o) = matches.opt_str("o") { o } else { free_args[1].clone() };
        }
    }

    let password = matches.opt_str("p").unwrap_or_else(|| helpers::prompt_for_password(false));

    match read_file(&filename) {
        Ok(filedata) => {
            match encrypt(&filedata, &password) {
                Ok(encrypted_data) => {
                    
                    let encrypted_data_bytes = encrypted_data.into_bytes();
                    info!("Appending {} encrypted bytes of data to stub", &encrypted_data_bytes.len());

                    let delimiter_header = render_delimiter("header");
                    let delimiter_footer = render_delimiter("footer");

                    let mut stub_data = read_file(&__file.absolute).unwrap();

                    stub_data.extend_from_slice(&delimiter_header.as_bytes());
                    stub_data.extend_from_slice(&encrypted_data_bytes);
                    stub_data.extend_from_slice(&delimiter_footer.as_bytes());

                    // write stub
                    if let Err(e) = write_file(&outfile, &stub_data) {
                        error!("Failed to stub to disk: {}. {}", outfile, e);
                        process::exit(1);
                    } else {

                        match chmod_x(&outfile) {
                            Ok(_r) => {
                                info!("Made file executable {}", outfile);
                            }
                            Err(e) => {
                                warn!("Failed to chmod file. {}", e)
                            }
                        }

                        //let check_outfile = get_file_details(&outfile).unwrap();
                        //print!("{:#?}", &check_outfile);

                        info!("Encrypted stub written to disk {}", outfile);
                        process::exit(0);
                    }
                },
                Err(e) => {
                    error!("Error encrypting file: {}", e);
                    process::exit(1);
                }
            }
        },
        Err(e) => {
            error!("Failed read_file: {}. {}", filename, e);
            process::exit(1);
        }
    }
}

