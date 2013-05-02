package com.redhat.victims;

import java.util.ArrayList;
import java.util.HashMap;

import com.redhat.victims.fingerprint.Fingerprint;
import com.redhat.victims.fingerprint.Metadata;

/**
 * The main container for a hash map data structure used to store victims record
 * information.
 * 
 * @author abn
 * 
 */
@SuppressWarnings("serial")
public class VictimsRecord extends HashMap<Constants, Object> {
	/**
	 * Maintains a list of value types that can be added to the record.
	 */
	protected static ArrayList<Class<?>> PERMITTED_VALUE_TYPES = new ArrayList<Class<?>>();
	static {
		PERMITTED_VALUE_TYPES.add(VictimsRecord.class);
		PERMITTED_VALUE_TYPES.add(String.class);
		PERMITTED_VALUE_TYPES.add(ArrayList.class);
		PERMITTED_VALUE_TYPES.add(Fingerprint.class);
		PERMITTED_VALUE_TYPES.add(Metadata.class);
	};

	public VictimsRecord() {
		super();
	}

	@Override
	public Object put(Constants key, Object value)
			throws IllegalArgumentException {
		if (!PERMITTED_VALUE_TYPES.contains(value.getClass())) {
			System.out.println(key.toString());
			throw new IllegalArgumentException(String.format(
					"Values of class type <%s> are not permitted in <%s>",
					value.getClass().getName(), this.getClass().getName()));
		}
		return super.put(key, value);
	}
}
