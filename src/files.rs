// files.rs
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::fs;
use std::fs::File;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;

use crate::helpers::{b64_encode};

pub fn render_delimiter(_str: &str) -> String {
    let _str = format!("__binkey__{}", _str);
    let encoded = b64_encode(_str);
    encoded
}

#[derive(Debug)]
pub struct FileDetails {
    pub exists: bool,
    pub absolute: String,
    pub filename: String,
    pub extension: Option<String>,
    pub filesize: u64,
    pub has_footer: bool,
    pub delimiter_header_len: u64,
    pub delimiter_header_pos: u64,
    pub delimiter_footer_pos: u64,
}

pub fn get_file_details(file_path: &str) -> io::Result<FileDetails> {
    let path = Path::new(file_path);

    let exists = path.exists();

    let metadata = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    let absolute = fs::canonicalize(&path)?.to_string_lossy().into_owned();

    let filename = path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let extension = path.extension()
        .map(|ext| ext.to_string_lossy().into_owned());

    let filesize = metadata.len();

    // check delimiters
    let delimiter_header = render_delimiter("header");
    let delimiter_footer = render_delimiter("footer");

    let delimiter_header_len = delimiter_header.as_bytes().len() as u64;

    let mut file = File::open(&path)?;
    let has_footer = delimiter_footer_exists(&path, delimiter_footer.as_bytes())?;

    let delimiter_header_pos;
    let delimiter_footer_pos;

    if has_footer {
        file.seek(SeekFrom::Start(0))?; // Reset file pointer before searching
        delimiter_header_pos = delimiter_header_len + find_delimiter_position(&mut file, delimiter_header.as_bytes())?;

        file.seek(SeekFrom::Start(0))?; // Reset file pointer again before next search
        delimiter_footer_pos = find_delimiter_position(&mut file, delimiter_footer.as_bytes())?;
    } else {
        delimiter_header_pos = 0;
        delimiter_footer_pos = 0;
    }

    Ok(FileDetails {
        exists,
        absolute,
        filename,
        extension,
        filesize,
        has_footer,
        delimiter_header_len,
        delimiter_header_pos,
        delimiter_footer_pos,
    })
}

// quick check to see if it has our footer
fn delimiter_footer_exists(file_path: &Path, marker: &[u8]) -> io::Result<bool> {
    let mut file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    let marker_size = marker.len() as u64;
    if file_size < marker_size {
        return Ok(false);
    }

    let mut buffer = vec![0; marker_size as usize];
    file.seek(SeekFrom::End(-(marker_size as i64)))?;
    file.read_exact(&mut buffer)?;

    Ok(buffer == marker)
}

pub fn find_delimiter_position(file: &mut File, delimiter: &[u8]) -> io::Result<u64> {
    const BUFFER_SIZE: usize = 1024 * 8;

    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut position: u64 = 0;
    let delimiter_len = delimiter.len() as u64;

    loop {
        let mut buffer = vec![0; BUFFER_SIZE];
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read == 0 {
            break; // eof
        }

        if let Some(found) = buffer.windows(delimiter_len as usize)
            .position(|window| window == delimiter) {
            return Ok(position + found as u64);
        }

        position += bytes_read as u64;
        
        if bytes_read >= delimiter_len as usize {
            let overlap = delimiter_len as i64 - 1;
            reader.seek(SeekFrom::Current(-overlap))?;
            position -= overlap as u64;
        }
    }

    Ok(0)
}

pub fn extract_encrypted_data(file: &mut File, start_pos: u64, end_pos: u64) -> io::Result<String> {
    let data_length = end_pos - start_pos;
    file.seek(SeekFrom::Start(start_pos))?;

    let mut buffer = vec![0; data_length as usize];
    file.read_exact(&mut buffer)?;

    let encrypted_data = String::from_utf8(buffer)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8 error"))?;

    Ok(encrypted_data)
}

pub fn chmod_x(file_path: &str) -> io::Result<()> {
    let metadata = fs::metadata(file_path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(file_path, permissions)
}

pub fn read_file(file_path: &str) -> io::Result<Vec<u8>> {
    fs::read(file_path)
}

pub fn write_file(file_path: &str, data: &[u8]) -> io::Result<()> {
    fs::write(file_path, data)
}

