package net.sandboxol.gpt.util;

import java.util.HashMap;
import java.util.Map;


public class KeysHolder {
	public static final String ROOT = "_ROOT";
	private static final Map<String, KeysNode> CACHE = new HashMap<>();
	
	/**
	 * @param child name of the keys,  not null
	 * @param parent name of the keys, not null
	 * @return KeysNode for the name
	 */
	public static KeysNode get(String name,String parent) {	
		if(name==null||parent==null) {return null;}
		if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		return setAndReturn(name,new KeysNode(name,get(parent)));
	}

	/**
	 * @param name keys' name
	 * @return KeysNode for the name, if name is null, it will return the _ROOT
	 */
	private static KeysNode get(String name) {	
		if(name==null||ROOT.equalsIgnoreCase(name)){
			return getRoot();
		}else if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		return setAndReturn(name,new KeysNode(name,getRoot()));
	}
	
	/**
	 * @return root KeysNode
	 */
	private static KeysNode getRoot() {
		if(CACHE.containsKey(ROOT)) {
			return CACHE.get(ROOT);
		}
		return setAndReturn(ROOT,new KeysNode(ROOT));
	}
	
	public static void setRoot(java.security.KeyPair kp) {
		CACHE.clear();
		CACHE.put(ROOT,new KeysNode(ROOT,kp));
	}
	
	
	private static KeysNode setAndReturn(String name, KeysNode keyGen) {
		CACHE.put(name,keyGen);
		return keyGen;
	}

	
}
