package com.redhat.victims.fingerprint;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import org.apache.commons.io.IOUtils;

/**
 * Implements handing of Archive files for fingerprinting.
 * 
 * @author abn
 * 
 */
public class JarFile extends AbstractFile {
	/**
	 * Indicates if archive contents get processed. Default is true.
	 */
	public static boolean RECURSIVE = true;
	private static final int BUFFER = 2048;

	protected ArrayList<Object> contents;
	protected HashMap<String, String> contentFingerprint;
	protected HashMap<String, String> metadata;
	protected JarInputStream jis;

	/**
	 * 
	 * @param bytes
	 *            A byte array containing the bytes of the file
	 * @param fileName
	 *            Name of the file being provided as bytes
	 * @throws IOException
	 */
	public JarFile(byte[] bytes, String fileName) throws IOException {
		this.contents = new ArrayList<Object>();
		this.metadata = new HashMap<String, String>();
		this.fileName = fileName;
		this.jis = new JarInputStream(new ByteArrayInputStream(bytes));
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Content file;
		while ((file = getNextFile()) != null) {
			bos.write(file.bytes);

			// Handle metadata/special cases
			if (file.name.toLowerCase().endsWith("pom.properties")) {
				// handle pom files
				InputStream is = new ByteArrayInputStream(file.bytes);
				metadata.putAll(Metadata.fromPom(is));
			}

			// This is separate as we may or may not want to fingerprint
			// all files.
			if (RECURSIVE) {
				HashMap<String, Object> record = Processor.process(file.bytes,
						file.name);
				if (record != null) {
					contents.add(record);
				}
			}
		}

		// Process the metadata from the manifest if available
		Manifest mf = jis.getManifest();
		if (mf != null) {
			metadata.putAll(Metadata.fromManifest(mf));
		}

		// TODO: decide if we want to keep the content-only hash
		this.contentFingerprint = Processor.fingerprint(bos.toByteArray());
		this.fingerprints = Processor.fingerprint(bytes);
		bos.close();
		jis.close();
	}

	/**
	 * 
	 * @param fileName
	 *            Name of the file being process, expected as path on disk.
	 * @throws IOException
	 */
	public JarFile(String fileName) throws IOException {
		this(new FileInputStream(fileName), fileName);
	}

	/**
	 * 
	 * @param is
	 *            The file as an input stream.
	 * @param fileName
	 *            The name of the file provided by the stream.
	 * @throws IOException
	 */
	public JarFile(InputStream is, String fileName) throws IOException {
		this(IOUtils.toByteArray(is), fileName);
	}

	public HashMap<String, Object> getRecord() {
		HashMap<String, Object> result = super.getRecord();
		result.put(Processor.CONTENT_KEY, contents);
		result.put(Processor.CONTENT_FINGERPRINT_KEY, contentFingerprint);
		if (metadata.size() > 0) {
			result.put(Processor.METADATA_KEY, metadata);
		}
		return result;
	}

	/**
	 * 
	 * @return
	 * @throws IOException
	 */
	protected Content getNextFile() throws IOException {
		JarEntry entry;
		while ((entry = jis.getNextJarEntry()) != null) {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] data = new byte[BUFFER];
			while (jis.read(data, 0, BUFFER) != -1) {
				bos.write(data);
			}
			Content file = new Content(entry.getName(), bos.toByteArray());
			bos.close();
			return file;
		}
		return null;
	}

	/**
	 * Content -- Inner class for use by {@link ArchiveFile}. This is used to
	 * group name of file extracted in memory and the corresponding bytes that
	 * were read.
	 * 
	 * @author abn
	 * 
	 */
	protected final class Content {
		public String name;
		public byte[] bytes;

		public Content(String name, byte[] bytes) {
			this.name = name;
			this.bytes = bytes;
		}
	}
}