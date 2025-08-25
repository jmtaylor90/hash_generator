#!/usr/bin/env python3
"""
Example usage of the hash_generator Python module.

This example demonstrates how to use the hash_generator library.
"""

import tempfile
import os
from pathlib import Path

# Import the hash_generator module
# Note: This assumes the module is built and available in Python path
try:
    import hash_generator
except ImportError:
    print("Error: hash_generator module not found.")
    print("Build the Python extension first with:")
    print("  cargo build --release --features python")
    print("  # or")
    print("  maturin develop --release --features python")
    exit(1)


def main():
    """Main example function demonstrating hash_generator usage."""
    
    print("🔥 Hash Generator Python Example")
    print("=" * 50)
    
    # Create a temporary file for demonstration
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
        content = "Hello, world! This is a test file for SHA256 hashing."
        tmp_file.write(content)
        tmp_file_path = tmp_file.name
    
    try:
        print(f"📁 Created test file: {tmp_file_path}")
        print(f"📄 Content: {content}")
        print(f"📏 Content length: {len(content)} bytes")
        
        # Example 1: Calculate hash using the main function
        print("\n1️⃣ Calculating hash using calculate_file_hash():")
        
        file_hash = hash_generator.calculate_file_hash(tmp_file_path)
        
        print(f"   Path: {file_hash.path}")
        print(f"   Hash: {file_hash.hash}")
        print(f"   Size: {file_hash.size} bytes")
        print(f"   Repr: {file_hash}")
        
        # Example 2: Verify the hash
        print("\n2️⃣ Verifying hash:")
        is_valid = file_hash.verify()
        print(f"   File verification: {'✅ Valid' if is_valid else '❌ Invalid'}")
        
        # Example 3: Convert to dictionary
        print("\n3️⃣ Converting to dictionary:")
        hash_dict = file_hash.to_dict()
        print(f"   Dictionary: {hash_dict}")
        
        # Example 4: Create FileHash manually
        print("\n4️⃣ Creating FileHash instance manually:")
        manual_hash = hash_generator.FileHash(
            path=file_hash.path,
            hash=file_hash.hash,
            size=file_hash.size
        )
        print(f"   Manual FileHash: {manual_hash}")
        print(f"   Matches original: {'✅ Yes' if manual_hash.hash == file_hash.hash else '❌ No'}")
        
        # Example 5: Modify file and verify again
        print("\n5️⃣ Testing file change detection:")
        
        # Modify the file
        with open(tmp_file_path, 'w') as f:
            f.write("Modified content - this should change the hash!")
        
        # Try to verify the original hash (should fail)
        is_still_valid = file_hash.verify()
        print(f"   Original hash after modification: {'✅ Still valid' if is_still_valid else '❌ Invalid (expected)'}")
        
        # Calculate new hash
        new_hash = hash_generator.calculate_file_hash(tmp_file_path)
        print(f"   New hash: {new_hash.hash}")
        print(f"   Hash changed: {'✅ Yes (expected)' if new_hash.hash != file_hash.hash else '❌ No'}")
        
        # Example 6: Error handling
        print("\n6️⃣ Error handling examples:")
        
        # Try non-existent file
        try:
            hash_generator.calculate_file_hash("/non/existent/file.txt")
        except Exception as e:
            print(f"   Non-existent file error: {type(e).__name__}: {e}")
        
        # Try invalid FileHash creation
        try:
            hash_generator.FileHash("test.txt", "invalid_hash", 100)
        except Exception as e:
            print(f"   Invalid hash error: {type(e).__name__}: {e}")
        
        print("\n✅ Example completed successfully!")
        
    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_file_path)
            print(f"🗑️  Cleaned up temporary file: {tmp_file_path}")
        except OSError:
            pass


if __name__ == "__main__":
    main()