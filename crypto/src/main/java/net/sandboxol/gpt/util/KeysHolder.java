package net.sandboxol.gpt.util;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class KeysHolder implements ECConstants,ECConstant {
	private static final int STRENTH = CURVE.getN().bitLength()>>>2;
	private static final ProviderConfiguration BCCONF = BouncyCastleProvider.CONFIGURATION;
	private KeysHolder parent;
	private KeyPair keys;
	private BigInteger pub;
	private String name;
	static{ if( Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null ) {
				Security.addProvider(new BouncyCastleProvider());
	}}

	public KeysHolder(String name) {
		this.name=name;
		this.initialize();
	}

	public KeysHolder(String name, KeysHolder parent) {
		this.name=name;
		this.parent=parent;
		this.initialize();
	}

	public KeysHolder(String name, KeyPair keys) {
		this.name=name;
		this.keys=keys;
	}

	public KeysHolder getParent() {
		return this.parent;
	}
	
	public KeysHolder getChild(String subName){
		return new KeysHolder(subName,this);
	}	
	
	public String getName() {
		return name;
	}

	public String getQName() {
		return (parent == null || parent.getName() == null) ? getName() : (parent.getQName() + "/" + getName());
	}
	
	/**
	 *  we use parent seed as seed if exists parent; use name as hmac secret ;
	 *  seed  = Hash.hmacSha256(secret, seed);
	 * @return seed BigInteger as private seed 
	 * 
	 */
	private void initialize() {
		if(name==null||getPrivate()!=null){return;};
		byte[] seed = (parent==null)?name.getBytes():parent.getPrivate().toByteArray();
		this.keys = createKeys(createSeed(name,seed));
	}
	
	KeyPair getKeys() {
		return keys;
	}
	
	BigInteger getPrivate() {
		if(keys==null||keys.getPrivate()==null){
			return null;
		}
		return ((ECPrivateKey)keys.getPrivate()).getS();
	}
	
	/**
	 * @return pubicPoint XY encoding without compressed
	 */
	public BigInteger getPublic() {
		if(this.pub!=null) {return this.pub;}
		if(keys==null||keys.getPublic()==null){
			return null;
		}
		byte[] encoded = ((BCECPublicKey)keys.getPublic()).getQ().getEncoded(false);
		this.pub = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length)); 
		return this.pub;
	}
	
	/**
	 *  we use parent key as seed; use child name as hmac secret ;
	 *  seed  = Hash.hmacSha256(secret, seed);
	 * @return seed BigInteger as private seed 
	 */
	public static BigInteger createSeed(String name, byte[] seed){
		byte[] salt = name.getBytes();
		byte[] data = seed;
		BigInteger N =CURVE.getN();
		BigInteger d = ZERO;
		do {
			data = Hash.hmacSha256(salt, data);
			d =  Numeric.toBigInt(data);
			if(d.compareTo(ZERO)<0||(d.compareTo(N)>0)) {
				d = d.mod(CURVE.getN());
			}
		}while(checkNafWeight(d));
		
		//if (keyIsOct){hex2Oct(d);} 
		// return new BigInteger(1,Arrays.copyOfRange(hmac, 0, 32));
		return d;		

	}
	
	public static KeyPair createKeys(BigInteger d){
        ECPrivateKeyParameters pri = new ECPrivateKeyParameters(d,CURVE);
        ECPublicKeyParameters  pub = new ECPublicKeyParameters(pointFrom(d),CURVE);
        //{@link org.bouncycastle.crypto.generators.ECKeyPairGenerator#generateKeyPair()}
		//{@link org.bouncycastle.crypto.generators.DSTU4145KeyPairGenerator#generateKeyPair()}
		//{@link org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC#generateKeyPair()}
        return new KeyPair(new BCECPublicKey("EC",pub,BCCONF), new BCECPrivateKey("EC",pri,BCCONF));

	}
	
	/**
	 * Create a keypair using SECP-256k1 curve.
	 * <p> Private keypairs are encoded using PKCS8
	 * <p> Private keys are encoded using X.509
	 * @throws GeneralSecurityException 
	 */
	public static KeyPair createKeys() throws GeneralSecurityException  {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
		//keyPairGenerator.initialize(ecGenParameterSpec,new SecureRandom());
		keyPairGenerator.initialize(ecGenParameterSpec);
		return keyPairGenerator.generateKeyPair();
	}

	
	/**
	 * 
	 * Return a point for Multiply the curve.G
	 * eg: public key point from the given private key.
	 *
	 * @param d the bigInteger for PointCombMultiplier
	 * @return ECPoint 
	 */
	public static ECPoint pointFrom(BigInteger d) {
		return new FixedPointCombMultiplier().multiply(CURVE.getG(), d);
	}
	
    //{@link org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$EC#strength=239}
    public static boolean checkNafWeight(BigInteger k) {
        if (k.signum() == 0) { return false; }
        BigInteger _3k = k.shiftLeft(1).add(k);
        BigInteger diff = _3k.xor(k);
        return diff.bitCount()>STRENTH;
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
		signer.init(true,  new ECPrivateKeyParameters(getPrivate(),CURVE));		
		BigInteger[] sign = signer.generateSignature(hash);		
		return Sign.createSignatureData(sign[0],sign[1], getPublic(), hash);
	}
	
	public static boolean verify(byte[] hash, String sign) {
		byte[] bytes = Numeric.hexStringToByteArray(sign);
		if(bytes.length!=65) {return false;}
		int recId = bytes[0]-27;
		BigInteger sigR = Numeric.toBigInt(bytes, 1, 32);
		BigInteger sigS = Numeric.toBigInt(bytes, 33, 32);
		ECPoint q = Sign.recoverPublicPoint(recId, sigR, sigS, hash);
		ECPublicKeyParameters pubKey = new ECPublicKeyParameters(q, CURVE);

		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		signer.init(false, pubKey);		
		return signer.verifySignature(hash,sigR,sigS);		
	}
	
	
	public String toString() {//avoid print private;
		StringBuilder sb = new StringBuilder(); 
		sb.append("ADDRESS:").append(Address.from(getPublic())).append(';');
		sb.append("PUBKEY:").append(Numeric.toHexStringWithPrefixSafe(getPublic())).append(';');
		sb.append("QName:").append(getQName()).append(';');
		return sb.toString();
	}	

	// btc address算法不一样：https://www.zhihu.com/question/22399196/answer/201836128

}
