// Copyright (c) 2025
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::types::PyModule;
use pyo3::Bound;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::{FileHash, calculate_hash};

/// Custom error type for input validation
#[derive(Debug)]
enum ValidationError {
    EmptyPath,
    InvalidPath(String),
    PathTooLong,
    NonUTF8Path,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::EmptyPath => "Path cannot be empty",
            Self::NonUTF8Path => "Path contains invalid UTF-8 characters",
            Self::PathTooLong => "Path length exceeds maximum allowed",
            Self::InvalidPath(err) => err,
        };
        write!(f, "{}", msg)
    }
}

/// Represents file hash information in Python
#[pyclass(name = "FileHash")]
#[derive(Clone)]
struct PyFileHash {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    hash: String,
    #[pyo3(get)]
    size: u64,
}

#[pymethods]
impl PyFileHash {
    /// Create a new FileHash instance
    ///
    /// Args:
    ///     path: File path (must be valid UTF-8)
    ///     hash: SHA256 hash string (must be valid hex)
    ///     size: File size in bytes
    ///
    /// Raises:
    ///     ValueError: If path is empty or hash is not valid hex
    #[new]
    fn new(path: String, hash: String, size: u64) -> PyResult<Self> {
        // Validate path
        if path.is_empty() {
            return Err(PyValueError::new_err("Path cannot be empty"));
        }

        // Validate hash format (must be valid hex string)
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PyValueError::new_err(
                "Hash must be a valid hexadecimal string",
            ));
        }

        // Validate hash length (SHA256 = 64 hex chars)
        if hash.len() != 64 {
            return Err(PyValueError::new_err(
                "Hash must be 64 characters long (SHA256)",
            ));
        }

        Ok(Self { path, hash, size })
    }

    /// String representation of the FileHash
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "FileHash(path='{}', hash='{}', size={})",
            self.path, self.hash, self.size
        ))
    }

    /// String representation of the FileHash (same as __repr__)
    fn __str__(&self) -> PyResult<String> {
        self.__repr__()
    }

    /// Convert to a Python dictionary
    ///
    /// Returns:
    ///     dict: Dictionary containing path, hash, and size
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path.clone())?;
        dict.set_item("hash", self.hash.clone())?;
        dict.set_item("size", self.size)?;
        Ok(dict)
    }

    /// Check if the file still exists and has the same hash
    ///
    /// Returns:
    ///     bool: True if the file exists and hash matches
    fn verify(&self) -> PyResult<bool> {
        match calculate_file_hash(self.path.clone()) {
            Ok(current) => Ok(current.hash == self.hash),
            Err(_) => Ok(false),
        }
    }
}

impl From<FileHash> for PyFileHash {
    fn from(hash: FileHash) -> Self {
        Self {
            path: hash.path,
            hash: hash.hash,
            size: hash.size,
        }
    }
}

/// Validate a file path
fn validate_path(path: &str) -> Result<PathBuf, ValidationError> {
    if path.is_empty() {
        return Err(ValidationError::EmptyPath);
    }

    // Check path length (platform-specific limits)
    #[cfg(windows)]
    if path.len() > 260 {
        return Err(ValidationError::PathTooLong);
    }
    #[cfg(unix)]
    if path.len() > 4096 {
        return Err(ValidationError::PathTooLong);
    }

    // Attempt to create PathBuf and check for invalid characters
    match PathBuf::from_str(path) {
        Ok(path_buf) => {
            // Additional validation for path components
            if path_buf.components().count() == 0 {
                return Err(ValidationError::InvalidPath("Empty path".to_string()));
            }

            // Check for invalid characters in path
            if cfg!(windows) && path.contains(['<', '>', ':', '"', '|', '?', '*']) {
                return Err(ValidationError::InvalidPath(
                    "Contains invalid Windows path characters".to_string(),
                ));
            }

            Ok(path_buf)
        }
        Err(_) => Err(ValidationError::NonUTF8Path),
    }
}

/// Calculate the SHA256 hash of a file
///
/// Args:
///     path: Path to the file to hash
///
/// Returns:
///     FileHash: Object containing file path, hash, and size
///
/// Raises:
///     ValueError: If the path is invalid
///     IOError: If the file cannot be read
#[pyfunction]
fn calculate_file_hash(path: String) -> PyResult<PyFileHash> {
    // Validate and convert path
    let path_buf = match validate_path(&path) {
        Ok(pb) => pb,
        Err(e) => return Err(PyValueError::new_err(e.to_string())),
    };

    // Calculate hash
    match calculate_hash(&path_buf) {
        Ok(hash) => {
            // Additional validation of the hash result
            let py_hash = PyFileHash::new(hash.path, hash.hash, hash.size)?;
            Ok(py_hash)
        }
        Err(e) => Err(PyIOError::new_err(e.to_string())),
    }
}

/// Python module initialization
#[pymodule]
fn hash_generator(_py: Python<'_>, m: Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFileHash>()?;
    m.add_function(wrap_pyfunction!(calculate_file_hash, &m)?)?;
    m.add("__doc__", "High-performance file hashing library with Rust backend.\n\nThis module provides fast SHA256 hashing capabilities for files using a Rust implementation.")?;
    Ok(())
}
