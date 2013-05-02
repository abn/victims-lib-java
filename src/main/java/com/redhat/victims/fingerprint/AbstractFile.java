package com.redhat.victims.fingerprint;

import com.redhat.victims.Constants;
import com.redhat.victims.VictimsRecord;

/**
 * Provides an abstract class for all file types that can be fingerprinted.
 * 
 * @author abn
 * 
 */
public abstract class AbstractFile implements FingerprintInterface {
	protected Fingerprint fingerprint = null;
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
	public Fingerprint getFingerprint() {
		return fingerprint;
	}

	public VictimsRecord getRecord() {
		VictimsRecord result = new VictimsRecord();
		result.put(Constants.KEY_FILENAME, fileName);
		result.put(Constants.KEY_FINGERPRINT, fingerprint);
		return result;
	}
}
