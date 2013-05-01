package com.redhat.victims.fingerprint;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;

import org.apache.commons.codec.binary.Hex;

public class Processor {
	private static ArrayList<String> ALGORITHMS = new ArrayList<String>();
	private static DefaultHashMap<String, Class<?>> TYPE_MAP = 
			new DefaultHashMap<String, Class<?>>(File.class);
	public static String CONTENT_KEY = "content";
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

}
