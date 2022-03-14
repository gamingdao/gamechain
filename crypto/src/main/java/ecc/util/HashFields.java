package ecc.util;

import java.util.HashSet;
import java.util.Set;

public interface HashFields {
	public static final String HASH_FIELD= "hash";
	public static final String SIGN_FIELD= "sign";
	@SuppressWarnings("serial")
	public static final Set<String> FIELDS_NOT_IN_HASH = new HashSet<String>(){{
		add(HASH_FIELD);add(SIGN_FIELD);	
	}};
	public static boolean ignore(Object key) {
		if(FIELDS_NOT_IN_HASH.contains(key)) {
			return true;
		}
		return false;
	}
}
