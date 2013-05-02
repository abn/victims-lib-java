package com.redhat.victims.fingerprint;

import java.util.HashMap;

/**
 * Provides an abstract class for all file types that can be fingerprinted.
 * 
 * @author abn
 * 
 */
public abstract class AbstractFile implements FingerprintInterface {
	protected HashMap<String, String> fingerprints = null;
	protected String fileName = null;

	/**
	 * @return the fileName
	 */
	public String getFileName() {
		return fileName;
	}

	/**
	 * @return the fingerprints
	 */
	public HashMap<String, String> getFingerprints() {
		return fingerprints;
	}

	public HashMap<String, Object> getRecord() {
		HashMap<String, Object> result = new HashMap<String, Object>();
		result.put(Processor.FILENAME_KEY, this.fileName);
		result.put(Processor.FINGERPRINT_KEY, fingerprints);
		return result;
	}
}
