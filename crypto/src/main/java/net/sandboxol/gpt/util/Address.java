package net.sandboxol.gpt.util;

import java.math.BigInteger;
import java.util.Arrays;

public class Address {
	public static final String HEX_PREFIX = "0x";
	public static final int ADDRESS_BITS = 160;
	public static final int PUBLIC_BITS = 512;
	
	public static String from(BigInteger publicKey) {
		return from(Numeric.toHexStringNoPrefixZeroPadded(publicKey, PUBLIC_BITS>>2));
	}

	public static String from(String publicKey) {
		String publicKeyNoPrefix = Numeric.cleanHexPrefix(publicKey);
		if (publicKeyNoPrefix.length() < PUBLIC_BITS>>2) {
			publicKeyNoPrefix = Strings.zeros((PUBLIC_BITS>>2)-publicKeyNoPrefix.length()) + publicKeyNoPrefix;
			//TODO check: need add prefix 0?
		}
		String hash = Hash.sha3(publicKeyNoPrefix);
		return HEX_PREFIX+hash.substring(hash.length() - (ADDRESS_BITS>>2)); // right most 160 bits
	}

	public static byte[] from(byte[] publicKey) {
		byte[] hash = Hash.sha3(publicKey);
		return Arrays.copyOfRange(hash, hash.length - (ADDRESS_BITS>>3), hash.length); // right most 160 bits
	}

	/**
	 * Checksum address encoding as per <a href=
	 * "https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md">EIP-55</a>.
	 *
	 * @param address a valid hex encoded address
	 * @return hex encoded checksum address
	 */
	public static String toChecksum(String address) {
		String lowercaseAddress = Numeric.cleanHexPrefix(address).toLowerCase();
		String addressHash = Numeric.cleanHexPrefix(Hash.sha3String(lowercaseAddress));
		StringBuilder result = new StringBuilder(lowercaseAddress.length() + 2);
		result.append(HEX_PREFIX);
		for (int i = 0; i < lowercaseAddress.length(); i++) {
			if (Integer.parseInt(String.valueOf(addressHash.charAt(i)), 16) >= 8) {
				result.append(String.valueOf(lowercaseAddress.charAt(i)).toUpperCase());
			} else {
				result.append(lowercaseAddress.charAt(i));
			}
		}
		return result.toString();
	}

}
