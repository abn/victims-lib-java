package com.redhat.victims.fingerprint;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.IOUtils;

public class ArchiveFile extends AbstractFile {
	public static boolean RECURSIVE = true;
	private static final int BUFFER = 2048;

	protected ArrayList<Object> contents;
	protected HashMap<String, String> contentFingerprint;
	protected ZipInputStream zis;

	public ArchiveFile(byte[] bytes, String fileName) throws IOException {
		this.contents = new ArrayList<Object>();
		this.fileName = fileName;
		this.zis = new ZipInputStream(new ByteArrayInputStream(bytes));
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Content file;
		while ((file = getNextFile()) != null) {
			bos.write(file.bytes);
			if (RECURSIVE) {
				String fileType = getFileType(file.name);
				if (!Processor.isKnownType(fileType)) {
					// Only handle types we know about eg: .class .jar
					continue;
				}
				Class<?> cls = Processor.getProcessor(fileType);
				try {
					if (AbstractFile.class.isAssignableFrom(cls)) {
						Constructor<?> ctor = cls.getConstructor(byte[].class,
								String.class);
						Object object = ctor.newInstance(new Object[] {
								file.bytes, file.name });
						HashMap<String, Object> record = ((AbstractFile) object)
								.getRecord();
						contents.add(record);
					}
				} catch (Exception e) {
					// TODO: Handle bad file
				}
			}
		}

		// TODO: decide if we want to keep the content-only hash
		this.contentFingerprint = Processor.fingerprint(bos.toByteArray());
		this.fingerprints = Processor.fingerprint(bytes);
		bos.close();
		zis.close();
	}

	public ArchiveFile(String fileName) throws IOException {
		this(new FileInputStream(fileName), fileName);
	}

	public ArchiveFile(InputStream is, String fileName) throws IOException {
		this(IOUtils.toByteArray(is), fileName);
	}

	public HashMap<String, Object> getRecord() {
		HashMap<String, Object> result = super.getRecord();
		result.put(Processor.CONTENT_KEY, contents);
		result.put(Processor.CONTENT_FINGERPRINT_KEY, contentFingerprint);
		return result;
	}

	protected String getFileType(String name) {
		// TODO: Handle things like tar.gz ??
		String[] tokens = name.split("\\.(?=[^\\.]+$)");
		if (tokens.length > 1) {
			return "." + tokens[tokens.length - 1].toLowerCase();
		}
		return "";
	}

	protected Content getNextFile() throws IOException {
		ZipEntry entry;
		while ((entry = this.zis.getNextEntry()) != null) {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] data = new byte[BUFFER];
			while (this.zis.read(data, 0, BUFFER) != -1) {
				bos.write(data);
			}
			Content file = new Content(entry.getName(), bos.toByteArray());
			bos.close();
			return file;
		}
		return null;

	}

	protected final class Content {
		public String name;
		public byte[] bytes;

		public Content(String name, byte[] bytes) {
			this.name = name;
			this.bytes = bytes;
		}
	}

	public static void main(String argv[]) {
		for (int i = 0; i < argv.length; i++) {
			ArchiveFile af;
			try {
				af = new ArchiveFile(argv[i]);
				System.out.println(af.getRecord());
			} catch (IOException e) {
				// Silently ignore invalids
			}

		}
	}
}
