package com.redhat.victims.fingerprint;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * 
 * @author gcmurphy
 * 
 */
public class Metadata {

	/**
	 * Attempts to parse a pom.xml file.
	 * 
	 * @param is
	 *            An input stream containing the extracted POM file.
	 */
	public static HashMap<String, String> fromPom(InputStream is) {
		HashMap<String, String> metadata = new HashMap<String, String>();
		BufferedReader input = new BufferedReader(new InputStreamReader(is));
		try {
			String line;
			while ((line = input.readLine()) != null) {
				if (line.startsWith("#"))
					continue;
				String[] property = line.trim().split("=");
				if (property.length == 2)
					metadata.put(property[0], property[1]);
			}
		} catch (IOException e) {
			// Problems? Too bad!
		}
		return metadata;
	}

	/**
	 * Attempts to parse a MANIFEST.MF file.
	 * 
	 * @param is
	 *            An input stream containing the extracted manifest file.
	 */
	public static HashMap<String, String> fromManifest(InputStream is) {
		HashMap<String, String> metadata = new HashMap<String, String>();
		Manifest mf;
		try {
			mf = new Manifest(is);
			final String[] attribs = {
					Attributes.Name.MANIFEST_VERSION.toString(),
					Attributes.Name.IMPLEMENTATION_TITLE.toString(),
					Attributes.Name.IMPLEMENTATION_URL.toString(),
					Attributes.Name.IMPLEMENTATION_VENDOR.toString(),
					Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString(),
					Attributes.Name.IMPLEMENTATION_VERSION.toString(),
					Attributes.Name.MAIN_CLASS.toString() };
			for (String attrib : attribs) {
				Object o = mf.getEntries().get(attrib);
				if (o != null) {
					metadata.put(attrib, o.toString());
				}
			}
		} catch (IOException e) {
			// Problems? Too bad!
		}
		return metadata;
	}

}
