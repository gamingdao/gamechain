package net.sandboxol.gpt.util;

import java.math.BigInteger;
import java.util.Arrays;

public class Address implements ECConstant {

	/**
	 * @param pKey the public key bytes
	 * @return address from the public Key
	 */
	public static String from(byte[] pKey) {
		if(pKey==null) {return null;}
		byte[] keys = Arrays.copyOfRange(pKey,pKey.length-(PUBLIC_BITS>>3), pKey.length);
		byte[] hash = Hash.sha3(keys);
		byte[] addr = Arrays.copyOfRange(hash,hash.length-(ADDRESS_BITS>>3),hash.length); // right most 160 bits
		return Numeric.toHexString(addr);
	}

	/**
	 * @param publicKey string encoding
	 * @return address from the publicKey
	 */
	public static String from(String publicKey) {
		if(publicKey.length()<=(ADDRESS_BITS>>2)+2){	//the input is a address?
			return publicKey;
		}
		byte[] bytes = Numeric.toBytesPadded(publicKey, PUBLIC_BITS>>3);
		return from(bytes);
	}
	
	/**
	 * @param publicKey the public key
	 * @return address from the public Key
	 */
	public static String from(BigInteger publicKey) {
		if(publicKey==null) {return null;}
		byte[] bytes = Numeric.toBytesPadded(publicKey, PUBLIC_BITS>>3);
		//byte[] bytes = publicKey.toByteArray();
		return from(bytes);
	}
	
	/**
	 * @param hash
	 * @param sign
	 * @return address recover the address from sign with the hash
	 */
	public static String from(byte[] hash, String sign) {
		return from(new SignData(hash,sign).getPublicKey());
	}

	/**
	 * Checksum address encoding as per <a href=
	 * "https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md">EIP-55</a>.
	 *
	 * @param address a valid hex encoded address
	 * @return hex encoded checksum address
	 */
	public static String toChecksum(String address) {
		if(address==null) {return null;}
		String lowercase = Numeric.cleanHexPrefix(address).toLowerCase();
		String addrHash = Numeric.cleanHexPrefix(Hash.sha3String(lowercase));
		StringBuilder result = new StringBuilder(lowercase.length() + 2);
		result.append(HEX_PREFIX);
		for (int i = 0; i < lowercase.length(); i++) {
			char c = lowercase.charAt(i);
			if(c>'9' && addrHash.charAt(i)>'7'){ c -= 32; }//need to UpperCase
			result.append(c);
		}
		return result.toString();
	}

}
