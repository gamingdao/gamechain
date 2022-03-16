/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package net.sandboxol.gpt.util;

import static net.sandboxol.gpt.util.Assertions.verifyPrecondition;
import static net.sandboxol.gpt.util.ECConstant.CURVE;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

/**
 * Transaction signing logic.
 *
 * <p>
 * Adapted from the <a href="https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/ECKey.java"> BitcoinJ ECKey</a> implementation.
 */
public class SignTool {
	
    /**
	 * @param recId   Which possible key to recover.
	 * @param sig     the R and S components of the signature, wrapped.
	 * @param hash Hash of the data that was signed.
	 * @return An ECKey containing only the public part, or null if recovery wasn't possible.
	 */
	public static BigInteger recoverPublicKeys(int recId, BigInteger sigR, BigInteger sigS, byte[] hash) {
		ECPoint q = recoverPublicPoint(recId, sigR, sigS, hash);
		if(q==null) {return null;}
		byte[] qBytes = q.getEncoded(false);
		// We remove the prefix
		return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
	}	

	/**
	 * Given the components of a signature and a selector value, recover and return the public key that generated the signature according to the algorithm in SEC1v2 section 4.1.6.
	 *
	 * <p>
	 * The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the correct one. 
	 * Because the key recovery operation yields multiple potential keys, the correct key must either be stored alongside the signature, 
	 * or you must be willing to try each recId in turn until you find one that outputs the key you are expecting.
	 *
	 * <p>
	 * If this method returns null it means recovery was not possible and recId should be iterated.
	 *
	 * <p>
	 * Given the above two points, a correct usage of this method is inside a for loop from 0 to 3, and if the output is null OR a key that is not the one you expect, you try again with the next recId.
	 *
	 * @param recId   Which possible key to recover.
	 * @param R     the components.R of the signature.
	 * @param S     the components.S of the signature.
	 * @param hash Hash of the data that was signed.
	 * @return An ECPoint of the public key, or null if recovery wasn't possible.
	 */
	public static ECPoint recoverPublicPoint(int recId, BigInteger R, BigInteger S, byte[] hash) {
		verifyPrecondition(recId >= 0, "recId must be positive");
		verifyPrecondition(hash != null, "message cannot be null");
		verifyPrecondition(R.signum() >= 0, "r must be positive");
		verifyPrecondition(S.signum() >= 0, "s must be positive");

		// 1.0 For j from 0 to h (h == recId here and the loop is outside this function)
		// 1.1 Let x = r + jn
		BigInteger i = BigInteger.valueOf((long) recId / 2);
		BigInteger n = CURVE.getN(); // Curve order.
		BigInteger x = R.add(i.multiply(n));
		// 1.2. Convert the integer x to an octet string X of length mlen using the conversion routine specified in Section 2.3.7, where mlen =(log2 p)/8 or mlen=m/8.
		// 1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the conversion routine specified in Section 2.3.4. If this conversion routine outputs "invalid", then do another iteration of Step 1.
		//
		// More concisely, what these points mean is to use X as a compressed public key.
		BigInteger prime = SecP256K1Curve.q;
		if (x.compareTo(prime) >= 0) {
			// Cannot have point co-ordinates larger than this as everything takes place modulo Q.
			return null;
		}
		// Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities. So it's encoded in the recId.
		ECPoint Q = decompressKey(x, (recId & 1) == 1);
		// 1.4. If nR != point at infinity, then do another iteration of Step 1 (callers
		// responsibility).
		if (!Q.multiply(n).isInfinity()) {
			return null;
		}
		// 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
		BigInteger e = new BigInteger(1, hash);
		// 1.6. For k from 1 to 2 do the following. (loop is outside this function via iterating recId)
		// 1.6.1. Compute a candidate public key as: Q = mi(r) * (sR - eG)
		//
		// Where mi(x) is the modular multiplicative inverse. We transform this into the following:
		// Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
		// Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
		// In the above equation ** is point multiplication and + is point addition (the EC group operator).
		//
		// We can find the additive inverse by subtracting e from zero then taking the mod. For
		// example the additive inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
		BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
		BigInteger rInv = R.modInverse(n);
		BigInteger srInv = rInv.multiply(S).mod(n);
		BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
		return ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, Q, srInv);
	}

	/** Decompress a compressed public key (x co-ord and low-bit of y-coord). */
	private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
		X9IntegerConverter x9 = new X9IntegerConverter();
		byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
		compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
		return CURVE.getCurve().decodePoint(compEnc);
	}
	
	/**
	 * 
	 * Will automatically adjust the S component to be less than or equal to half the curve order, if necessary. 
	 * This is required because for every signature (r,s) the signature (r, -s (mod N)) is a valid signature of the same message.
	 * However, we dislike the ability to modify the bits of a Bitcoin transaction after it's been signed, as that violates various assumed invariants. 
	 * Thus in future only one of those forms will be considered legal and the other will be banned.
	 *{@link SignTool#HALF_CURVE_ORDER}. See <a href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">BIP62</a>.
	 * @return the BigInteger in a canonicalised form.
	 */
	public static BigInteger canonicalize(BigInteger s) {
		if(s.compareTo(ECConstant.HALF_CURVE_ORDER)>0) {
			// The order of the curve is the number of valid points that exist on that curve. If S is in the upper half of the number of valid points, then bring it back to the lower half. 
			// Otherwise, imagine that N = 10, s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions. 10 - 8 == 2, giving us always the latter solution, which is canonical.
			return ECConstant.CURVE.getN().subtract(s);
		}
		return s;
		
	}

	public static SignData createSignatureData(BigInteger sigR, BigInteger sigS, BigInteger publicKey, byte[] hash) {
		// Now we have to work backwards to figure out the recId needed to recover the signature.
		sigS = canonicalize(sigS);
		int recId = -1;
		for (int i = 0; i < 4; i++) {
			BigInteger k = recoverPublicKeys(i, sigR, sigS, hash);
			if (k != null && k.equals(publicKey)) {
				recId = i;
				break;
			}
		}
		if (recId == -1) {
			throw new RuntimeException("Could not construct a recoverable key. Are your credentials valid?");
		}

		int header = recId + 27;
		return new SignData((byte) header, sigR, sigS, hash);
	}
	
	/**
	 * SignTool a message with the private key of this key pair.
	 *
	 * @param data the data need to sign
	 * @param needHash boolean true will Hash.sha3(data), false if the data NO need hash again
	 * @return An BigInteger[r,s] of the hash
	 */
	public static String sign(KeysInfo ki, byte[] data, boolean needHash) {
		byte[] hash = needHash? Hash.sha3(data):data;
		return sign(hash,ki).getEtherEncode();
	}
	
	/**
	 * SignTool a hash with the private key of this key pair.
	 *
	 * @param hash the hash data need to sign
	 * @return SignatureData with r,s,v
	 */
	public static SignData sign(byte[] hash, KeysInfo ki) {
		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		signer.init(true,  new ECPrivateKeyParameters(ki.getPrivate(),CURVE));		
		BigInteger[] sign = signer.generateSignature(hash);		
		return createSignatureData(sign[0],sign[1], ki.getPublic(), hash);
	}
	
	
	public static boolean verify(byte[] hash, String sign) {
		SignData sd = new SignData(hash,sign);
		ECPoint q = recoverPublicPoint(sd.getRecId(),sd.getR(),sd.getS(), hash);
		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(q, CURVE);
		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		signer.init(false, pubKey);		
		return signer.verifySignature(hash,sd.getR(),sd.getS());		
	}


}
