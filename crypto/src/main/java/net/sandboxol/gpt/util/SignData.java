package net.sandboxol.gpt.util;

import static org.bouncycastle.util.BigIntegers.TWO;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;


public class SignData {
	private final byte[] v;
	private final byte[] r;
	private final byte[] s;

	public SignData(byte v, byte[] r, byte[] s) {
		this(new byte[] { v }, r, s);
	}

	public SignData(byte[] v, byte[] r, byte[] s) {
		this.v = v;
		this.r = r;
		this.s = s;
	}

	public byte[] getV() {
		return v;
	}

	public byte[] getR() {
		return r;
	}

	public byte[] getS() {
		return s;
	}
	
	public String getEtherEncode() {
		byte[] bytes = new byte[r.length+s.length+1];
		bytes[0]=getRealV(Numeric.toBigInt(getV()));
		System.arraycopy(r,0,bytes,1,r.length);
		System.arraycopy(s,0,bytes,r.length+1,s.length);
		return Numeric.toHexString(bytes);
	}
	
	public String getEncode() {
		String str = Numeric.toHexString(getV());
		str+= Numeric.toHexString(r,0,r.length,false);
		str+= Numeric.toHexString(s,0,s.length,false);
		return str;
	}
	

	static final int CHAIN_ID_INC = 35;
	static final int LOWER_REAL_V = 27;
	static byte getRealV(BigInteger bv) {
		long v = bv.longValue();
		if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
			return (byte) v;
		}
		byte realV = LOWER_REAL_V;
		int inc = 0;
		if ((int) v % 2 == 0) {
			inc = 1;
		}
		return (byte) (realV + inc);
	}

	 Long getChainId() {
		BigInteger bv = Numeric.toBigInt(getV());
		long v = bv.longValue();
		if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
			return null;
		}
		return (v - CHAIN_ID_INC) / 2;
	}

	String getFrom() throws SignatureException {
		byte[] encodedTransaction = null;// getEncodedTransaction(getChainId());
		BigInteger v = Numeric.toBigInt(getV());
		SignData signatureDataV = new SignData(getRealV(v), getR(), getS());
		BigInteger key = SignTool.signedMessageToKey(encodedTransaction, signatureDataV);
		return "0x" + Address.from(key);
	}


	/**
	 * Returns recovery ID.
	 *
	 * @param signatureData The message signature components
	 * @param chainId       of the network
	 * @return int recovery ID
	 */
	public int getRecId( long chainId) {
		BigInteger v = Numeric.toBigInt(getV());
		BigInteger lowerRealV = BigInteger.valueOf(LOWER_REAL_V);
		BigInteger lowerRealVPlus1 = BigInteger.valueOf(LOWER_REAL_V + 1);
		BigInteger chainIdInc = BigInteger.valueOf(CHAIN_ID_INC);
		if (v.equals(lowerRealV) || v.equals(lowerRealVPlus1)) {
			return v.subtract(lowerRealV).intValue();
		} else if (v.compareTo(chainIdInc) > 0) {
			return v.subtract(BigInteger.valueOf(chainId).multiply(TWO)).add(chainIdInc).intValue();
		} else {
			throw new RuntimeException(String.format("Unsupported format exception", v));
		}
	}

	/**
	 * Returns the header 'v'.
	 *
	 * @param recId The recovery id.
	 * @return byte[] header 'v'.
	 */
	public static byte[] getVFromRecId(int recId) {
		return new byte[] { (byte) (LOWER_REAL_V + recId) };
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

		if (!Arrays.equals(v, that.v)) {
			return false;
		}
		if (!Arrays.equals(r, that.r)) {
			return false;
		}
		return Arrays.equals(s, that.s);
	}

	@Override
	public int hashCode() {
		int result = Arrays.hashCode(v);
		result = 31 * result + Arrays.hashCode(r);
		result = 31 * result + Arrays.hashCode(s);
		return result;
	}
}