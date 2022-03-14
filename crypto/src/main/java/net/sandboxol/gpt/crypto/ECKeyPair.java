package net.sandboxol.gpt.crypto;

import static net.sandboxol.gpt.util.CurveConstant.CURVE;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import net.sandboxol.gpt.util.Hash;
import net.sandboxol.gpt.util.Numeric;
import net.sandboxol.gpt.util.Sign;
import net.sandboxol.gpt.util.SignData;

/** Elliptic Curve SECP-256k1 generated key pair. */
public class ECKeyPair {
	static final String ROOT = "GPT_ROOT";
	private static final Map<String, ECKeyPair> CACHE = new HashMap<>();
	private final BigInteger privateKey;
	private final BigInteger publicKey;
	private String name;
	private ECKeyPair parent;
	static boolean needCache = true;
	static boolean keyIsOct = false;

	public ECKeyPair(BigInteger privateKey, BigInteger publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}
	
	public ECKeyPair(String name, BigInteger privateKey, ECKeyPair parent) {
		this.privateKey = privateKey;
		this.publicKey = publicKeyFromPrivate(privateKey);
		this.parent = parent;
		this.name = name;
		if (needCache) {
			CACHE.put(getQName(), this);
		}
		;// todo:avoid conflict name
	}

	public BigInteger getPublicKey() {
		return publicKey;
	}

	BigInteger getPrivateKey() {
		return privateKey;
	}

	/**
	 * @return the eth chain address
	 */
	public String getAddress() {
		return Keys.toChecksumAddress(Keys.getAddress(getPublicKey()));
	}

	// btc address算法不一样：https://www.zhihu.com/question/22399196/answer/201836128

	static BigInteger newPrivateKey(String keyName, byte[] seed) {
		// byte[] hmac = Hash.hmacSha512(keyName.getBytes(),seed);
		// return new BigInteger(1,Arrays.copyOfRange(hmac, 0, 32));
		byte[] pkn = Hash.hmacSha256(keyName.getBytes(), seed);
		if (keyIsOct){hex2Oct(pkn);} // to comments;
		return new BigInteger(1, pkn);
	}

	static final void hex2Oct(byte[] hex) {
		for (int i = 0; i < hex.length; i++) {
			hex[i] = (byte)(oct(hex[i]>>4)<<4 | oct(hex[i]));
		}
	}
	private static final byte oct(int src) {
		int oct = src & 7;
		if (oct == 0 || oct == 4) {
			oct = oct >> 2 | 1 << 3;
		}
		return (byte)oct;
	}

	/**
	 * @return applicaion root Keypair
	 */
	static ECKeyPair create() {
		ECKeyPair gkp = getCache(ROOT);
		if (gkp != null) {
			return gkp;
		}
		BigInteger priKey = newPrivateKey(ROOT, (ROOT+ROOT).getBytes());// should from outer
		return new ECKeyPair(ROOT, priKey, null);
	}

	ECKeyPair create(String keyName) {
		if (keyName == null || (parent == null && !ROOT.endsWith(getName()))) {// should initialized;
			return null;
		}
		String QName = getQName() + "." + keyName.trim();
		ECKeyPair gkp = getCache(QName);
		if (gkp != null) {
			return gkp;
		}
		BigInteger priKey = newPrivateKey(keyName, getPrivateKey().toByteArray());
		return new ECKeyPair(keyName, priKey, this);
	}

	/**
	 * for user
	 * 
	 * @param keyName
	 * @param parentName
	 * @return
	 */
	static ECKeyPair create(String keyName, String upName) {
		if (keyName == null) {
			return null;
		}
		ECKeyPair root = create();
		ECKeyPair parent = (upName == null || ROOT.equalsIgnoreCase(upName)) ? root : root.create(upName);
		return parent.create(keyName);
	}


	private static ECKeyPair getCache(String name) {
		return CACHE.containsKey(ROOT) ? CACHE.get(name) : null;
	}

	public String getQName() {
		return (parent == null || parent.getName() == null) ? getName() : (parent.getQName() + "/" + getName());
	}

	public String getName() {
		return name == null || name.trim().isEmpty()? null : name.trim();
	}

	void print(String prefix) {
		String addr = getAddress();
		if (allIsOct(addr)) {
			System.out.println("All is OctNumber: ");
		} else if (!addr.startsWith(prefix == null ? "0x" : prefix)) {
			return;
		}
		System.out.print("ADDRESS:" + addr);
		System.out.print(";PUBKEY:" + Numeric.toHexStringWithPrefixSafe(getPublicKey()));
		System.out.print(";PRIKEY:" + Numeric.toHexStringWithPrefixSafe(getPrivateKey()));
		System.out.println(";QName:" + getQName());
	}

	// 十进制
	private static boolean allIsOct(String str) {
		for (int i = 2, n = str.length(); i < n; i++) {
			char c = str.charAt(i);
			if (c < '0' || c > '9') {
				return false;
			}
		}
		return true;
	}

	/**
	 * Sign a message with the private key of this key pair.
	 *
	 * @param data the data need to sign
	 * @param needHash boolean true will Hash.sha3(data), false if the data NO need hash again
	 * @return An BigInteger[r,s] of the hash
	 */
	public String sign(byte[] data, boolean needHash) {
		byte[] hash = needHash? Hash.sha3(data):data;
		return sign(hash).getEtherEncode();
	}
	
	/**
	 * Sign a hash with the private key of this key pair.
	 *
	 * @param hash the hash data need to sign
	 * @return SignatureData with r,s,v
	 */
	public SignData sign(byte[] hash) {
		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(getPrivateKey(), CURVE);
		signer.init(true, privKey);		
		BigInteger[] sign = signer.generateSignature(hash);		
		return Sign.createSignatureData(sign[0],sign[1], getPublicKey(), hash);
	}
	
	public static boolean verify(byte[] hash, String sign) {
		byte[] bytes = Numeric.hexStringToByteArray(sign);
		if(bytes.length!=65) {return false;}
		int recId = bytes[0]-1;
		BigInteger sigR = Numeric.toBigInt(bytes, 1, 32);
		BigInteger sigS = Numeric.toBigInt(bytes, 33, 32);
		ECPoint q = Sign.recoverPublicPoint(recId, sigR, sigS, hash);
		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(q, CURVE);

		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		signer.init(false, pubKey);		
		return signer.verifySignature(hash,sigR,sigS);		
	}

	/**
	 * Returns public key from the given private key.
	 *
	 * @param privKey the private key to derive the public key from
	 * @return BigInteger encoded public key
	 */
	public static BigInteger publicKeyFromPrivate(BigInteger privKey) {
		ECPoint point = publicPointFromPrivate(privKey);

		byte[] encoded = point.getEncoded(false);
		return new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length)); // remove prefix
	}

	/**
	 * Returns public key point from the given private key.
	 *
	 * @param privKey the private key to derive the public key from
	 * @return ECPoint public key
	 */
	public static ECPoint publicPointFromPrivate(BigInteger privKey) {
		/*
		 * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than
		 * the group order, but that could change in future versions.
		 */
		if (privKey.bitLength() > CURVE.getN().bitLength()) {
			privKey = privKey.mod(CURVE.getN());
		}
		return new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
	}
	
	ECPrivateKeyParameters getPrivateKeyParameters () {
		return new ECPrivateKeyParameters(getPrivateKey(), CURVE);
	}
	
	public ECPublicKeyParameters getPublicKeyParameters () {
		ECPoint point = publicPointFromPrivate(getPrivateKey());
		return new ECPublicKeyParameters(point, CURVE);
	}

}
