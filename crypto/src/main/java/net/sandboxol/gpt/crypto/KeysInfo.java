package net.sandboxol.gpt.crypto;

import java.util.HashMap;
import java.util.Map;

import net.sandboxol.gpt.util.KeysHolder;


public class KeysInfo {
	public static final String ROOT = "_ROOT";
	private static final Map<String, KeysHolder> CACHE = new HashMap<>();
	
	/**
	 * @return root KeysHolder
	 */
	static KeysHolder getRoot() {
		if(CACHE.containsKey(ROOT)) {
			return CACHE.get(ROOT);
		}
		return setAndReturn(ROOT,new KeysHolder(ROOT));
	}

	/**
	 * @param name
	 * @param parent
	 * @return KeysHolder for the name
	 */
	public static KeysHolder get(String name,String parent) {	
		if(name ==null) {return null;}
		if(CACHE.containsKey(name)) {
			return CACHE.get(name);
		}
		KeysHolder pk;
		if(parent==null||ROOT.equalsIgnoreCase(parent)) {
			pk = getRoot();
		}else if(CACHE.containsKey(parent)) {
			pk = CACHE.get(parent);
		}else {
			pk = setAndReturn(parent,new KeysHolder(parent,getRoot()));
		}
		return setAndReturn(name,new KeysHolder(parent,pk));
	}
	
	private static KeysHolder setAndReturn(String name, KeysHolder keyGen) {
		CACHE.put(name,keyGen);
		return keyGen;
	}
}
