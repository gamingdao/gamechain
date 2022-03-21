package net.sandboxol.gpt.crypto;

import net.sandboxol.gpt.util.Address;
import net.sandboxol.gpt.util.Hash;
import net.sandboxol.gpt.util.KeysHolder;
import net.sandboxol.gpt.util.KeysNode;
import net.sandboxol.gpt.util.SignData;
import net.sandboxol.gpt.util.SignTool;

public class KeysTool {
	private KeysNode keysNode;
	
	public KeysTool(String childName, String groupName) {
		this.keysNode = KeysHolder.get(childName, groupName);
	}
	
	public String getAddress() {
		String addr = Address.from(keysNode.getPublic());
		return Address.toChecksum(addr);
	}
	
	/**
	 * Sign a hash with the private key.
	 * @param hash the hash data need to sign
	 * @return SignatureData with r,s,v
	 */
	public SignData sign(byte[] hash) {
		 return SignTool.sign(hash,keysNode);
	} 

	/**
	 * SignTool a message with the private key.
	 *
	 * @param data the data need to sign
	 * @param needHash boolean true will Hash.sha3(data), false if the data NO need hash again
	 * @return An BigInteger[r,s] of the hash
	 */
	public String sign(byte[] data, boolean needHash) {
		byte[] hash = needHash? Hash.sha3(data):data;
		return SignTool.sign(hash,keysNode).getEtherEncode();
	}
	
	/**
	 * @param hash data hash of sign generated from 
	 * @param sign to be verified 
	 * @return true if the sign match the hash
	 */
	public static boolean verify(byte[] hash, String sign) {
		return SignTool.verify(hash, sign);
	}

	public static String getAddress(byte[] hash, String sign) {
		return Address.toChecksum(Address.from(hash,sign));
	}

	

}
