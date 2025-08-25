# Hash Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance Rust application and library for generating SHA256 hashes of files.

## Features

- Parallel file processing using Rayon
- Memory-efficient buffered I/O
- Multiple output formats (JSON, JSONL, CSV)
- Progress indicator for large directories
- Can be used as both a CLI application and a library

## Installation

```shell
cargo install hash_generator
```

## CLI Usage

```shell
# Generate hashes for all files in a directory
hash_generator \
  --read-directory /path/to/files \
  --output-file hashes.json \
  --output-format json

# Supported output formats: json, jsonl, csv
hash_generator \
  --read-directory /path/to/files \
  --output-file hashes.csv \
  --output-format csv
```

## Library Usage

The `hash_generator` crate can be used as a library in other Rust projects.
Add it to your `Cargo.toml`:

```toml
[dependencies]
hash_generator = "0.1.0"
```

### Example: File Integrity Verification

```rust
use hash_generator::{FileHash, calculate_hash};
use std::path::PathBuf;

fn verify_file_integrity(path: &str, expected_hash: &str) -> bool {
    let result = calculate_hash(&PathBuf::from(path)).unwrap();
    result.hash == expected_hash
}

fn main() {
    let is_valid = verify_file_integrity(
        "important_file.txt",
        "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
    );
    println!("File integrity check: {}", if is_valid { "PASSED" } else { "FAILED" });
}
```

### API Reference

#### `FileHash` Struct

```rust
pub struct FileHash {
    pub path: String,   // Path to the file
    pub hash: String,   // SHA256 hash of the file contents
    pub size: u64,      // File size in bytes
}
```

#### `calculate_hash` Function

```rust
pub fn calculate_hash(path: &PathBuf) -> Result<FileHash>
```

Calculates the SHA256 hash of a file, returning a `FileHash` struct containing the file's path, hash, and size.

## Performance

- Uses parallel processing for handling multiple files
- Employs buffered I/O for efficient file reading
- Streams output to avoid memory overhead with large directories

## Python Bindings

The `hash_generator` library provides Python bindings that allow you to
leverage Rust's performance in your Python projects. The bindings offer a
Pythonic interface while maintaining all the benefits of Rust's memory safety
and parallel processing capabilities.

### Prerequisites

Before installing the Python package, ensure you have:

1. Python 3.7 or later installed
2. Rust toolchain (can be installed via [rustup](https://rustup.rs/))
3. Python development headers:
    - Ubuntu/Debian: `sudo apt-get install python3-dev`
    - macOS: Included with Python
    - Windows: Included with Python from python.org

### Installation Options

#### From PyPI (Recommended)

```shell
pip install hash-generator
```

#### From Source

1. Clone the repository:

    ```shell
    git clone https://github.com/yourusername/hash_generator
    cd hash_generator
    ```

2. Install using pip:

    ```shell
    pip install maturin
    maturin develop
    ```

### Python API Reference

#### FileHash Class

```python
class FileHash:
    """
    Represents the hash information for a file.
    
    Attributes:
        path (str): Path to the file
        hash (str): SHA256 hash of the file contents
        size (int): Size of the file in bytes
    """
    
    def to_dict(self) -> dict:
        """Convert the FileHash object to a dictionary."""
        pass
```

#### Functions

```python
def calculate_file_hash(path: str) -> FileHash:
    """
    Calculate the SHA256 hash of a file.
    
    Args:
        path: Path to the file to hash
        
    Returns:
        FileHash: Object containing the file's path, hash, and size
        
    Raises:
        IOError: If the file cannot be read or doesn't exist
    """
    pass
```

### Usage Examples

#### Basic File Hashing

```python
import hash_generator

# Calculate hash for a single file
try:
    result = hash_generator.calculate_file_hash("example.txt")
    print(f"File: {result.path}")
    print(f"Hash: {result.hash}")
    print(f"Size: {result.size} bytes")
except IOError as e:
    print(f"Error: {e}")
```

#### File Integrity Verification

```python
def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
    """
    Verify a file's integrity by comparing its hash.
    
    Args:
        file_path: Path to the file to verify
        expected_hash: Expected SHA256 hash
        
    Returns:
        bool: True if the file's hash matches the expected hash
    """
    try:
        result = hash_generator.calculate_file_hash(file_path)
        return result.hash == expected_hash
    except IOError:
        return False

# Example usage
is_valid = verify_file_integrity(
    "important_file.txt",
    "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
)
print(f"File integrity: {'PASSED' if is_valid else 'FAILED'}")
```

#### Working with Hash Results

```python
import hash_generator
import json

def process_file_hash(file_path: str) -> None:
    result = hash_generator.calculate_file_hash(file_path)
    
    # Access attributes directly
    print(f"File path: {result.path}")
    print(f"SHA256 hash: {result.hash}")
    print(f"File size: {result.size} bytes")
    
    # Convert to dictionary for JSON serialization
    hash_dict = result.to_dict()
    json_output = json.dumps(hash_dict, indent=2)
    print(f"JSON format:\n{json_output}")

# Example usage
process_file_hash("example.txt")
```

#### Handling Multiple Files

```python
import hash_generator
from pathlib import Path

def hash_directory(directory: str) -> list[dict]:
    """
    Calculate hashes for all files in a directory.
    
    Args:
        directory: Path to the directory to process
        
    Returns:
        list[dict]: List of file hash information dictionaries
    """
    results = []
    for path in Path(directory).rglob('*'):
        if path.is_file():
            try:
                file_hash = hash_generator.calculate_file_hash(str(path))
                results.append(file_hash.to_dict())
            except IOError as e:
                print(f"Error processing {path}: {e}")
    return results

# Example usage
hashes = hash_directory("./documents")
for hash_info in hashes:
    print(f"{hash_info['path']}: {hash_info['hash']}")
```

### Error Handling

The Python bindings convert Rust errors into appropriate Python exceptions:

```python
import hash_generator

try:
    result = hash_generator.calculate_file_hash("nonexistent_file.txt")
except IOError as e:
    print(f"File error: {e}")
    # Handle error appropriately
```

### Performance Notes

- The Rust implementation uses buffered I/O for efficient file reading
- Large files are processed in chunks to minimize memory usage
- File operations use native Rust implementations for optimal performance

### Thread Safety

The Python bindings are thread-safe and can be used with Python's threading
and multiprocessing libraries.
The underlying Rust code handles memory management and concurrency safely.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
