package com.redhat.victims.fingerprint;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

public class File extends AbstractFile {

	public File(byte[] bytes, String fileName) {
		this.fileName = fileName;
		this.fingerprints = Processor.fingerprint(bytes);
	}

	public File(InputStream is, String fileName) throws IOException {
		this(IOUtils.toByteArray(is), fileName);
	}

}
