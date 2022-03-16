package net.sandboxol.gpt.util;

import java.util.HashMap;
import java.util.Map;


public class KeysHolder {
	public static final String ROOT = "_ROOT";
	private static final Map<String, KeysInfo> CACHE = new HashMap<>();
	
	/**
	 * @param child name of the keys,  not null
	 * @param parent name of the keys, not null
	 * @return KeysInfo for the name
	 */
	public static KeysInfo get(String name,String parent) {	
		if(name==null||parent==null) {return null;}
		if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		return setAndReturn(name,new KeysInfo(name,get(parent)));
	}

	/**
	 * @param name keys' name
	 * @return KeysInfo for the name, if name is null, it will return the _ROOT
	 */
	private static KeysInfo get(String name) {	
		if(name==null||ROOT.equalsIgnoreCase(name)){
			return getRoot();
		}else if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		return setAndReturn(name,new KeysInfo(name,getRoot()));
	}
	
	/**
	 * @return root KeysInfo
	 */
	private static KeysInfo getRoot() {
		if(CACHE.containsKey(ROOT)) {
			return CACHE.get(ROOT);
		}
		return setAndReturn(ROOT,new KeysInfo(ROOT));
	}
	
	public static void setRoot(java.security.KeyPair kp) {
		CACHE.clear();
		CACHE.put(ROOT,new KeysInfo(ROOT,kp));
	}
	
	
	private static KeysInfo setAndReturn(String name, KeysInfo keyGen) {
		CACHE.put(name,keyGen);
		return keyGen;
	}

	
}
