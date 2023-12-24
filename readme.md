# binkey

## introduction
<img src="icon.svg" height="100" align="right" />
binkey is a rust-based encryption tool that transforms any file into a self-extracting, passphrase-protected executable. designed for secure distribution and storage of sensitive data, each encrypted file is a standalone entity, containing a copy of binkey itself, eliminating the need for a separate decryption tool.

## key features
- **self-contained executables**: each encrypted file is a complete executable, containing a copy of binkey for self-extraction.
- **passphrase protection**: secures files with aes-256 encryption, unlocked only with a user-defined passphrase.
- **delimiter-driven encryption**: utilizes unique delimiters to identify encrypted data segments within the binary.

## how it works
binkey employs base64 encoding and aes-256 encryption for securing files. each encrypted file is encapsulated between unique header and footer delimiters, marking the encrypted data segment within the binary.

### encryption
to encrypt a file:
```
binkey file [outfile] -p <passphrase>
```

### decryption
running the encrypted file prompts for the passphrase, allowing for decryption and extraction of the original content without needing an external binkey installation.

## building from source
to build the binkey binary
```
cargo build --release
```

## contributing
contributions to enhance binkey are always welcome. please follow standard github contribution guidelines.

