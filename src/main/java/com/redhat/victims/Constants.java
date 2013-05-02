package com.redhat.victims;

/**
 * Provides the constant values used in the library and their string
 * representations as required.
 * 
 * @author abn
 * 
 */
public enum Constants {
	// Keys used
	KEY_CONTENT,
	KEY_CONTENT_FINGERPRINT,
	KEY_FINGERPRINT,
	KEY_METADATA,
	KEY_FILENAME,

	// Algorithms
	MD5,
	SHA1,
	SHA512 {
		public String toString() {
			return "SHA-512";
		}
	}
}
