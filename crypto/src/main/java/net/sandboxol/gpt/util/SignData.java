package net.sandboxol.gpt.util;

import static net.sandboxol.gpt.util.Assertions.verifyPrecondition;

import java.math.BigInteger;
import java.util.Arrays;


public class SignData {
	private final byte v;
	private final byte[] r;
	private final byte[] s;
	private final byte[] h;
	private final BigInteger R;
	private final BigInteger S;

	/**
	 * @param v the header of sign
	 * @param R sign components.R
	 * @param S sign components.S
	 * @param hash the hash to be signed
	 */
	public SignData(byte v, BigInteger R, BigInteger S, byte[] hash) {
		this.h = hash;
		this.v = v;
		this.r = Numeric.toBytesPadded(R, 32);//R.toByteArray();
		this.s = Numeric.toBytesPadded(S, 32);//S.toByteArray();
		this.R = R;
		this.S = S;
	}

	/**
	 * @param hash the hash to be signed
	 * @param sign the sign result
	 */
	public SignData(byte[] hash, String sign) {
		byte[] bytes = Numeric.hexStringToByteArray(sign);
		//if(bytes.length!=65) {return;}
		this.h = hash;
		this.v = bytes[0];
		this.r = Arrays.copyOfRange(bytes,1,33);
		this.s = Arrays.copyOfRange(bytes,33,65);
		this.R = Numeric.toBigInt(r);
		this.S = Numeric.toBigInt(s);
	}

	public byte getV() {
		return v;
	}

	public BigInteger getR() {
		return R;
	}

	public BigInteger getS() {
		return S;
	}
	
	public String getEtherEncode() {
		byte[] bytes = new byte[r.length+s.length+1];
		bytes[0]=getEtherV(getV());
		System.arraycopy(r,0,bytes,1,r.length);
		System.arraycopy(s,0,bytes,r.length+1,s.length);
		return Numeric.toHexString(bytes);
	}
	
	public String getEncode() {
		String str = Numeric.toHexStringNoPrefix(new byte[] {getV()});
		str+= Numeric.toHexString(r,0,r.length,false);
		str+= Numeric.toHexString(s,0,s.length,false);
		return str;
	}
	
	static final String ETHER_MSG_PREFIX = "\u0019Ethereum Signed Message:\n";
	public static byte[] getEtherHash(byte[] message) {
		byte[] prefix = ETHER_MSG_PREFIX.concat(String.valueOf(message.length)).getBytes(); 
		byte[] result = new byte[prefix.length + message.length];
		System.arraycopy(prefix, 0, result, 0, prefix.length);
		System.arraycopy(message, 0, result, prefix.length, message.length);
		return Hash.sha3(result);
	}

	static final int CHAIN_ID_INC = 35;
	static final int LOWER_REAL_V = 27;
	static byte getEtherV(byte bv) {
		long v = bv;
		if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
			return (byte) v;
		}
		int etherV = LOWER_REAL_V + (v%2==0?1:0);
		return (byte) etherV;
	}

	/**
	 * Returns the header 'v'.
	 *
	 * @param recId The recovery id.
	 * @return byte[] header 'v'.
	 */
	public static byte getVFromRecId(int recId) {
		return (byte) (LOWER_REAL_V + recId);
	}

	Long getChainId() {
		long v = getV();
		if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
			return null;
		}
		return (v - CHAIN_ID_INC) / 2;
	}
	/**
	 * Returns recovery ID.
	 *
	 * @param signatureData The message signature components
	 * @param chainId       of the network
	 * @return int recovery ID
	 */
	public int getRecId(int chainId) {
		int v = getV();
		if (v==LOWER_REAL_V || (v-1)==LOWER_REAL_V) {
			return v-LOWER_REAL_V;
		} else if (v>CHAIN_ID_INC) {
			return v-chainId*2+CHAIN_ID_INC;
		} else {
			throw new RuntimeException(String.format("Unsupported format exception", v));
		}
	}
	public int getRecId() {
		if (v==LOWER_REAL_V || (v-1)==LOWER_REAL_V) {
			return v-LOWER_REAL_V;
		}
		return v;
	}
	
	/**
	 * Given an arbitrary message hash and an Ethereum message signature encoded in bytes, returns the public key that was used to sign it. 
	 * This can then be compared to the expected public key to determine if the signature was correct.
	 * @return the public key used to sign the message
	 * @throws RuntimeException If the public key could not be recovered or if there was a signature format error.
	 */
	public byte[] getPublicKey() {
		verifyPrecondition(r != null && r.length == 32, "r must be 32 bytes");
		verifyPrecondition(s != null && s.length == 32, "s must be 32 bytes");
		int header = getV() & 0xFF;
		// The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
		// 0x1D = second key with even y, 0x1E = second key with odd y
		if (header < LOWER_REAL_V || header >= CHAIN_ID_INC) {
			throw new RuntimeException("Signature header byte out of range: " + header);
		}
		return SignTool.recoverPublicKeys(header-LOWER_REAL_V,R,S, h);
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		SignData that = (SignData) o;

		if (v!=that.v) {
			return false;
		}
		if (!Arrays.equals(r, that.r)) {
			return false;
		}
		return Arrays.equals(s, that.s);
	}

	@Override
	public int hashCode() {
		int result = v;
		result = 31 * result + Arrays.hashCode(r);
		result = 31 * result + Arrays.hashCode(s);
		return result;
	}
}