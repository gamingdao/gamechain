/*
ECC: y^2=x^3+7 ;  y²=x³+7 Mod(P)
ECC推荐参数：256k1
p=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a=0000000000000000000000000000000000000000000000000000000000000000
b=0000000000000000000000000000000000000000000000000000000000000007
G=79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

ECC推荐参数：256r1
p=FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a=FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b=5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G=6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
  4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n=FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  ECC-256k1：
x = 0x79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
y = 0x483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
p = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
G =(x,y); G的阶为n
P = 2^256-2^32-977=2^256-2^32-2^10+2^5+2^4-1
    
 */
package ecc.util;

import java.math.BigInteger;
import java.security.SignatureException;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;

import ecc.crypto.Keys;
import ecc.crypto.Sign;

public interface ECOperations {

	final int CHAIN_ID_INC = 35;
	final int LOWER_REAL_V = 27;
	final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
	final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
	final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

	Sign.SignatureData getSignatureData();

	byte[] getEncodedTransaction(Long chainId);

	default String getFrom() throws SignatureException {
		byte[] encodedTransaction = getEncodedTransaction(getChainId());
		BigInteger v = Numeric.toBigInt(getSignatureData().getV());
		byte[] r = getSignatureData().getR();
		byte[] s = getSignatureData().getS();
		Sign.SignatureData signatureDataV = new Sign.SignatureData(getRealV(v), r, s);
		BigInteger key = Sign.signedMessageToKey(encodedTransaction, signatureDataV);
		return "0x" + Keys.getAddress(key);
	}

	default void verify(String from) throws SignatureException {
		String actualFrom = getFrom();
		if (!actualFrom.equals(from)) {
			throw new SignatureException("from mismatch");
		}
	}

	default byte getRealV(BigInteger bv) {
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

	default Long getChainId() {
		BigInteger bv = Numeric.toBigInt(getSignatureData().getV());
		long v = bv.longValue();
		if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
			return null;
		}
		return (v - CHAIN_ID_INC) / 2;
	}
}
