package com.redhat.victims.fingerprint;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

public class Processor {
	private static ArrayList<String> ALGORITHMS = new ArrayList<String>();
	private static DefaultHashMap<String, Class<?>> TYPE_MAP = 
			new DefaultHashMap<String, Class<?>>(File.class);
	public static String CONTENT_KEY = "content";
	public static String CONTENT_FINGERPRINT_KEY = "content-fingerprint";
	public static String FINGERPRINT_KEY = "fingerprint";
	public static String METADATA_KEY = "metadata";
	public static String FILENAME_KEY = "filename";

	// Static Initializations
	static {
		// Algorithms
		ALGORITHMS.add("SHA1");
		ALGORITHMS.add("MD5");
		ALGORITHMS.add("SHA-512");

		// File Types
		TYPE_MAP.put(".class", ClassFile.class);
		TYPE_MAP.put(".jar", ArchiveFile.class);
	}

	public static Class<?> getProcessor(String filetype) {
		return TYPE_MAP.get(filetype.toLowerCase());
	}

	public static boolean isKnownType(String fileType) {
		return TYPE_MAP.containsKey(fileType);
	}

	public static HashMap<String, Object> process(byte[] bytes, String fileName) {
		String fileType = Processor.getFileType(fileName);
		if (Processor.isKnownType(fileType)) {
			// Only handle types we know about eg: .class .jar
			Class<?> cls = Processor.getProcessor(fileType);
			try {
				if (AbstractFile.class.isAssignableFrom(cls)) {
					// TOOD: Maybe find a better way of doing this.
					Constructor<?> ctor = cls.getConstructor(byte[].class,
							String.class);
					Object object = ctor.newInstance(new Object[] { bytes,
							fileName });
					HashMap<String, Object> record = ((Interface) object)
							.getRecord();
					return record;
				}
			} catch (Exception e) {
				// TODO: Handle bad file
			}
		}
		return null;
	}

	public static HashMap<String, Object> process(InputStream is,
			String fileName) throws IOException {
		return process(IOUtils.toByteArray(is), fileName);
	}

	public static HashMap<String, Object> process(String fileName)
			throws IOException {
		FileInputStream fis = new FileInputStream(fileName);
		return process(fis, fileName);
	}

	protected static String getFileType(String name) {
		// TODO: Handle things like tar.gz ??
		String[] tokens = name.split("\\.(?=[^\\.]+$)");
		if (tokens.length > 1) {
			return "." + tokens[tokens.length - 1].toLowerCase();
		}
		return "";
	}

	public static HashMap<String, String> fingerprint(byte[] bytes) {
		HashMap<String, String> fingerprints = new HashMap<String, String>();
		for (String algorithm : ALGORITHMS) {
			try {
				MessageDigest md = MessageDigest.getInstance(algorithm
						.toUpperCase());
				fingerprints.put(algorithm,
						new String(Hex.encodeHex(md.digest(bytes))));
			} catch (NoSuchAlgorithmException e) {
				// Do nothing just skip
			}
		}
		return fingerprints;
	}

	protected static class DefaultHashMap<K, V> extends HashMap<K, V> {
		private static final long serialVersionUID = 1L;
		protected V defaultValue;

		public DefaultHashMap(V defaultValue) {
			super();
			this.defaultValue = defaultValue;
		}

		@Override
		public V get(Object k) {
			V v = super.get(k);
			return ((v == null) && !this.containsKey(k)) ? this.defaultValue
					: v;
		}
	}

	public static void main(String argv[]) {
		// Main method for testing
		// DEBUG CODE
		for (int i = 0; i < argv.length; i++) {
			try {
				HashMap<String, Object> record = process(argv[i]);
				System.out.println(record);
			} catch (IOException e) {
				// Silently ignore invalids
			}

		}
	}
}
