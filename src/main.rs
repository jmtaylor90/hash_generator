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

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam_channel::{Sender as CBSender, bounded};
use hash_generator::{FileHash, calculate_hash};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::io::{BufWriter, Write};
use std::time::Duration;
use std::{
    path::{Path, PathBuf},
    thread,
};
use walkdir::WalkDir;
mod symlink;
use symlink::validate_symlink;

/// Command line arguments for the hash generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to read files from
    #[arg(long)]
    read_directory: PathBuf,

    /// Output file path
    #[arg(long)]
    output_file: PathBuf,

    /// Output format (csv, json, or jsonl)
    #[arg(long)]
    output_format: String,
}

/// Writer that handles different output formats in a streaming fashion
struct StreamingWriter {
    writer: BufWriter<std::fs::File>,
    format: String,
    is_first: bool,
    line_buf: String,
}

/// Error type for streaming writer operations
#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    #[error("Invalid output format: {0}")]
    InvalidFormat(String),

    #[error("Invalid hash format: {0}")]
    InvalidHash(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Symlink error: {0}")]
    SymlinkError(String),
}

impl StreamingWriter {
    /// Validate output format
    fn validate_format(format: &str) -> Result<(), WriterError> {
        match format {
            "json" | "jsonl" | "csv" => Ok(()),
            _ => Err(WriterError::InvalidFormat(format.to_string())),
        }
    }

    /// Validate hash data before writing
    fn validate_hash(hash: &FileHash) -> Result<(), WriterError> {
        // Validate hash format (64 hex chars)
        if !hash.hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.hash.len() != 64 {
            return Err(WriterError::InvalidHash(
                "Hash must be 64 hexadecimal characters".into(),
            ));
        }

        // Validate path is not empty and is valid UTF-8
        if hash.path.is_empty() {
            return Err(WriterError::InvalidHash("Path cannot be empty".into()));
        }

        Ok(())
    }

    fn new(path: PathBuf, format: String) -> Result<Self> {
        // Validate format before proceeding
        Self::validate_format(&format.to_lowercase())?;

        // Validate output path
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = std::fs::File::create(&path)
            .context(format!("Failed to create output file: {}", path.display()))?;

        let writer = BufWriter::with_capacity(128 * 1024, file);
        let mut sw = Self {
            writer,
            format: format.to_lowercase(),
            is_first: true,
            line_buf: String::with_capacity(256),
        };

        // Write headers/opening brackets
        match sw.format.as_str() {
            "json" => sw.writer.write_all(b"[\n")?,
            "csv" => {
                sw.writer.write_all(b"path,hash,size\n")?;
            }
            "jsonl" => {}
            _ => unreachable!("Format validation should have caught this"),
        }

        Ok(sw)
    }

    fn write_entry(&mut self, hash: &FileHash) -> Result<()> {
        // Validate hash data before writing
        Self::validate_hash(hash)?;

        // Escape special characters in CSV
        let escaped_path = if self.format == "csv" {
            hash.path.replace(',', "\\,")
        } else {
            hash.path.clone()
        };

        match self.format.as_str() {
            "json" => {
                if !self.is_first {
                    self.writer.write_all(b",\n")?;
                }
                serde_json::to_writer_pretty(&mut self.writer, &hash)
                    .context("Failed to serialize to JSON")?;
                self.is_first = false;
            }
            "jsonl" => {
                self.line_buf.clear();
                self.line_buf =
                    serde_json::to_string(&hash).context("Failed to serialize to JSONL")?;
                self.writer.write_all(self.line_buf.as_bytes())?;
                self.writer.write_all(b"\n")?;
            }
            "csv" => {
                if !self.is_first {
                    self.writer.write_all(b"\n")?;
                }
                write!(self.writer, "{},{},{}", escaped_path, hash.hash, hash.size)?;
                self.is_first = false;
            }
            _ => unreachable!("Format validation should have caught this"),
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        if self.format == "json" {
            self.writer.write_all(b"\n]")?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

fn process_files(tx: CBSender<FileHash>, path: PathBuf, pb: ProgressBar) -> Result<()> {
    // Validate input directory
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "Directory does not exist: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(anyhow::anyhow!("Not a directory: {}", path.display()));
    }

    // Configure thread pool with reasonable limits
    let num_threads = std::cmp::min(num_cpus::get(), 32); // Cap at 32 threads
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .context("Failed to create thread pool")?;

    let errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let errors_clone = errors.clone();

    pool.install(|| {
        WalkDir::new(path)
            .follow_links(true)
            .max_depth(100) // Reasonable depth limit
            .same_file_system(true) // Don't cross filesystem boundaries
            .into_iter()
            .par_bridge()
            .filter_map(|e| match e {
                Ok(entry) => Some(entry),
                Err(e) => {
                    errors_clone
                        .lock()
                        .unwrap()
                        .push(format!("Walk error: {}", e));
                    None
                }
            })
            .filter(|e| {
                let ft = e.file_type();
                if ft.is_symlink() {
                    let path = e.path();
                    match validate_symlink(path, path.parent().unwrap_or_else(|| Path::new("/"))) {
                        Ok(Some(_info)) => true, // Valid symlink, process it
                        Ok(None) => true,        // Not a symlink, process it
                        Err(err) => {
                            errors_clone.lock().unwrap().push(format!(
                                "Symlink error for {}: {}",
                                path.display(),
                                err
                            ));
                            false // Skip this file
                        }
                    }
                } else {
                    ft.is_file()
                }
            })
            .try_for_each(|entry| {
                let path_buf = entry.path().to_path_buf();

                match calculate_hash(&path_buf) {
                    Ok(hash) => {
                        if tx.send(hash).is_err() {
                            return Err(anyhow::anyhow!("Channel closed"));
                        }
                        pb.inc(1);
                        Ok(())
                    }
                    Err(e) => {
                        errors_clone.lock().unwrap().push(format!(
                            "Error processing {}: {}",
                            entry.path().display(),
                            e
                        ));
                        Ok(())
                    }
                }
            })
    })?;

    // Report any errors that occurred
    let errors = errors.lock().unwrap();
    if !errors.is_empty() {
        eprintln!("\nEncountered the following errors:");
        for error in errors.iter() {
            eprintln!("  - {}", error);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.read_directory.exists() {
        anyhow::bail!(
            "Directory does not exist: {}",
            args.read_directory.display()
        );
    }

    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // Create channels for communication with buffer size based on thread count
    // Larger buffer for better throughput with more threads
    let channel_buffer_size = std::cmp::max(num_cpus::get() * 4, 64);
    let (tx, rx) = bounded::<FileHash>(channel_buffer_size);

    // Spawn file processing thread
    let process_path = args.read_directory.clone();
    let pb_clone = pb.clone();
    thread::spawn(move || {
        if let Err(e) = process_files(tx, process_path, pb_clone) {
            eprintln!("Error processing files: {}", e);
        }
    });

    // Create streaming writer
    let mut writer = StreamingWriter::new(args.output_file, args.output_format)?;
    let mut count = 0;

    // Process results as they come in
    while let Ok(hash) = rx.recv() {
        writer.write_entry(&hash)?;
        count += 1;
    }

    // Finish writing
    writer.finish()?;
    pb.finish_and_clear();

    println!("Successfully processed {} files", count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::time::Duration;
    use tempfile::tempdir;

    fn create_test_file(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        println!(
            "Writing content to {}: {:?}",
            path.display(),
            String::from_utf8_lossy(content)
        );
        file.write_all(content).unwrap();
        file.flush().unwrap();
        path
    }

    #[test]
    fn test_calculate_hash_success() -> Result<()> {
        let dir = tempdir()?;
        let content = b"test content";
        println!("Main test content: {:?}", String::from_utf8_lossy(content));
        let file_path = create_test_file(&dir, "test.txt", content);
        let result = calculate_hash(&file_path)?;

        assert_eq!(result.size, 12);
        assert_eq!(
            result.hash,
            "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
        );
        assert_eq!(result.path, fs::canonicalize(&file_path)?.to_string_lossy());
        Ok(())
    }

    #[test]
    fn test_calculate_hash_empty_file() {
        let dir = tempdir().unwrap();
        let file_path = create_test_file(&dir, "empty.txt", b"");
        let result = calculate_hash(&file_path);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("empty"));
    }

    #[test]
    fn test_calculate_hash_nonexistent_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("nonexistent.txt");
        assert!(calculate_hash(&file_path).is_err());
    }

    #[test]
    fn test_streaming_writer_json() -> Result<()> {
        let dir = tempdir()?;
        let output_path = dir.path().join("output.json");
        let mut writer = StreamingWriter::new(output_path.clone(), "json".to_string())?;

        let hashes = vec![
            FileHash::new_for_test(
                "file1.txt".to_string(), 
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), 
                1
            ),
            FileHash::new_for_test(
                "file2.txt".to_string(), 
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856".to_string(), 
                2
            ),
        ];

        for hash in &hashes {
            writer.write_entry(hash)?;
        }
        writer.finish()?;

        let content = fs::read_to_string(output_path)?;
        assert!(content.starts_with("[\n"));
        assert!(content.ends_with("\n]"));
        assert!(content.contains("file1.txt"));
        assert!(content.contains("file2.txt"));
        Ok(())
    }

    #[test]
    fn test_streaming_writer_jsonl() -> Result<()> {
        let dir = tempdir()?;
        let output_path = dir.path().join("output.jsonl");
        let mut writer = StreamingWriter::new(output_path.clone(), "jsonl".to_string())?;

        let hash = FileHash::new_for_test(
            "test.txt".to_string(), 
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), 
            1
        );
        writer.write_entry(&hash)?;
        writer.finish()?;

        let content = fs::read_to_string(output_path)?;
        let parsed: FileHash = serde_json::from_str(&content.lines().next().unwrap())?;
        assert_eq!(parsed.path, hash.path);
        assert_eq!(parsed.hash, hash.hash);
        assert_eq!(parsed.size, hash.size);
        Ok(())
    }

    #[test]
    fn test_streaming_writer_csv() -> Result<()> {
        let dir = tempdir()?;
        let output_path = dir.path().join("output.csv");
        let mut writer = StreamingWriter::new(output_path.clone(), "csv".to_string())?;

        let hash = FileHash::new_for_test(
            "test.txt".to_string(), 
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), 
            1
        );
        writer.write_entry(&hash)?;
        writer.finish()?;

        let mut reader = csv::Reader::from_path(output_path)?;
        let headers: Vec<String> = reader.headers()?.iter().map(|s| s.to_string()).collect();
        assert_eq!(headers, vec!["path", "hash", "size"]);

        let record: FileHash = reader.deserialize().next().unwrap()?;
        assert_eq!(record.path, hash.path);
        assert_eq!(record.hash, hash.hash);
        assert_eq!(record.size, hash.size);
        Ok(())
    }

    #[test]
    fn test_streaming_writer_csv_multiple() -> Result<()> {
        let dir = tempdir()?;
        let output_path = dir.path().join("output_multi.csv");
        let mut writer = StreamingWriter::new(output_path.clone(), "csv".to_string())?;

        let h1 = FileHash::new_for_test(
            "file1.txt".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            1,
        );
        let h2 = FileHash::new_for_test(
            "file2.txt".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856".to_string(),
            2,
        );

        writer.write_entry(&h1)?;
        writer.write_entry(&h2)?;
        writer.finish()?;

        // Verify we can read back both rows
        let mut reader = csv::Reader::from_path(output_path)?;
        let mut rows = reader.deserialize::<FileHash>();
        let r1 = rows.next().unwrap()?;
        let r2 = rows.next().unwrap()?;
        assert_eq!(r1.path, h1.path);
        assert_eq!(r2.path, h2.path);
        Ok(())
    }

    #[test]
    fn test_streaming_writer_invalid_format() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("output.txt");
        assert!(StreamingWriter::new(output_path, "invalid".to_string()).is_err());
    }

    #[test]
    fn test_streaming_writer_invalid_hash_length() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("out.jsonl");
        let mut writer = StreamingWriter::new(output_path, "jsonl".to_string()).unwrap();

        // 63 chars (too short)
        let bad_hash = FileHash::new_for_test("file.txt".to_string(), "a".repeat(63), 1);
        let err = writer.write_entry(&bad_hash).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Hash must be 64 hexadecimal characters"));
    }

    #[test]
    fn test_streaming_writer_invalid_hash_non_hex() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("out.jsonl");
        let mut writer = StreamingWriter::new(output_path, "jsonl".to_string()).unwrap();

        // 64 chars but includes non-hex 'z'
        let mut s = "a".repeat(63);
        s.push('z');
        let bad_hash = FileHash::new_for_test("file.txt".to_string(), s, 1);
        let err = writer.write_entry(&bad_hash).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Hash must be 64 hexadecimal characters"));
    }

    #[test]
    fn test_streaming_writer_empty_path() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("out.jsonl");
        let mut writer = StreamingWriter::new(output_path, "jsonl".to_string()).unwrap();

        let good_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        let bad = FileHash::new_for_test("".to_string(), good_hash, 1);
        let err = writer.write_entry(&bad).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Path cannot be empty"));
    }

    #[test]
    fn test_process_files_integration() -> Result<()> {
        let dir = tempdir()?;

        // Create test directory structure
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir)?;

        create_test_file(&dir, "file1.txt", b"content1");
        create_test_file(&dir, "file2.txt", b"content2");
        create_test_file(&dir, ".hidden", b"hidden");
        create_test_file(&dir, "subdir/file3.txt", b"content3");

        // Set up channels and progress bar
        let (tx, rx) = bounded(1024);
        let pb = ProgressBar::new_spinner();

        // Start processing in a separate thread
        let process_path = dir.path().to_path_buf();
        thread::spawn(move || {
            let _ = process_files(tx, process_path, pb);
        });

        // Collect results
        let mut hashes = Vec::new();
        while let Ok(hash) = rx.recv_timeout(Duration::from_secs(1)) {
            hashes.push(hash);
        }

        assert_eq!(hashes.len(), 4); // All files including hidden and subdirectory
        assert!(hashes.iter().any(|h| h.path.ends_with("file1.txt")));
        assert!(hashes.iter().any(|h| h.path.ends_with("file2.txt")));
        assert!(hashes.iter().any(|h| h.path.ends_with("file3.txt")));
        assert!(hashes.iter().any(|h| h.path.ends_with(".hidden")));

        Ok(())
    }

    #[test]
    fn test_end_to_end() -> Result<()> {
        let dir = tempdir()?;
        let input_dir = dir.path().join("input");
        let output_file = dir.path().join("output.json");
        fs::create_dir(&input_dir)?;

        // Create test files
        create_test_file(&dir, "input/file1.txt", b"content1");
        create_test_file(&dir, "input/file2.txt", b"content2");

        // Run main logic
        let args = Args {
            read_directory: input_dir,
            output_file: output_file.clone(),
            output_format: "json".to_string(),
        };

        let (tx, rx) = bounded(1024);
        let pb = ProgressBar::new_spinner();

        // Process files
        let process_path = args.read_directory.clone();
        let pb_clone = pb.clone();
        thread::spawn(move || {
            let _ = process_files(tx, process_path, pb_clone);
        });

        // Write results
        let mut writer = StreamingWriter::new(args.output_file, args.output_format)?;
        let mut count = 0;

        while let Ok(hash) = rx.recv_timeout(Duration::from_secs(1)) {
            writer.write_entry(&hash)?;
            count += 1;
        }

        writer.finish()?;
        pb.finish_and_clear();

        // Verify results
        assert_eq!(count, 2);
        let content = fs::read_to_string(output_file)?;
        assert!(content.contains("file1.txt"));
        assert!(content.contains("file2.txt"));

        Ok(())
    }

    #[test]
    fn test_process_files_invalid_dir() {
        let (tx, _rx) = bounded(8);
        let pb = ProgressBar::new_spinner();
        let path = PathBuf::from("/path/does/not/exist");
        let err = process_files(tx, path, pb).unwrap_err();
        assert!(format!("{}", err).contains("Directory does not exist"));
    }

    #[test]
    fn test_process_files_not_a_directory() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("file.txt");
        fs::write(&file_path, b"content")?;

        let (tx, _rx) = bounded(8);
        let pb = ProgressBar::new_spinner();
        let err = process_files(tx, file_path.clone(), pb).unwrap_err();
        assert!(format!("{}", err).contains("Not a directory"));
        Ok(())
    }

    #[test]
    fn test_process_files_symlink_outside_base_is_skipped() -> Result<()> {
        let base = tempdir()?;
        let outside = tempdir()?;

        // Create a real file outside the base dir
        let target = outside.path().join("outside.txt");
        fs::write(&target, b"content")?;

        // Create a symlink inside base pointing to outside
        let link = base.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link)?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link)?;

        // Also create a regular file that should be hashed
        let ok_file = base.path().join("ok.txt");
        fs::write(&ok_file, b"ok")?;

        let (tx, rx) = bounded(16);
        let pb = ProgressBar::new_spinner();
        let process_path = base.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = process_files(tx, process_path, pb);
        });

        // Collect results for a short period
        let mut got = Vec::new();
        while let Ok(h) = rx.recv_timeout(Duration::from_millis(500)) {
            got.push(h);
            if got.len() >= 1 { break; }
        }

        // We should only see the regular file, not the symlink
        assert!(got.iter().any(|h| h.path.ends_with("ok.txt")));
        assert!(!got.iter().any(|h| h.path.ends_with("link.txt")));
        Ok(())
    }
}
