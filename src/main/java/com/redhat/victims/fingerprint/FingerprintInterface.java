package com.redhat.victims.fingerprint;

import com.redhat.victims.VictimsRecord;

/**
 * The interface implemented by all implementations for handling fingerprinting.
 * 
 * @author abn
 * 
 */
public interface FingerprintInterface {

	/**
	 * Gets the hashmap of fingerprints
	 * 
	 * @return A hashmap of the for {algorithm:hash}
	 */
	public Fingerprint getFingerprint();

	/**
	 * Creates a 'record' with available info for the processed file. This
	 * includes fingerprints (all available algorithms), records of contents (if
	 * this is an archive), metadata (if available) etc.
	 * 
	 * @return A information record correspoding to the file processed.
	 */
	public VictimsRecord getRecord();

}
