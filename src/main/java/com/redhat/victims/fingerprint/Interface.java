package com.redhat.victims.fingerprint;

import java.util.HashMap;

/**
 * The interface implemented by all implementations for handling fingerprinting.
 * 
 * @author abn
 * 
 */
public interface Interface {

	/**
	 * Gets the hashmap of fingerprints
	 * 
	 * @return A hashmap of the for {algorithm:hash}
	 */
	public HashMap<String, String> getFingerprints();

	/**
	 * Creates a 'record' with available info for the processed file. This
	 * includes fingerprints (all available algorithms), records of contents (if
	 * this is an archive), metadata (if available) etc.
	 * 
	 * @return A information record correspoding to the file processed.
	 */
	public HashMap<String, Object> getRecord();
}
