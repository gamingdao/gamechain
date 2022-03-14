package net.sandboxol.gpt.util;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 椭圆曲线签名算法
 * 
 * 速度快 强度高 签名短
 * 
 * 实现方 JDK1.7/BC
 */
public class JDKSigner {

	private KeyPair keyPair = null;

	public JDKSigner(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public static JDKSigner getSigner(String keyName, String upName) {
		KeyPair pair = null;
		return new JDKSigner(pair);
	}
	
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException  {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(256);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 *@see {@link sun.security.provider.DSAKeyFactory#engineGeneratePrivate(KeySpec)};
	 */
	public byte[] sign(byte[] data) throws GeneralSecurityException {
		ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

		// 2.执行签名
		//sun.security.mscapi.CPublicKey.CECPublicKey.getEncoded();
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
		KeyFactory keyFactory = KeyFactory.getInstance("EC");

		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		Signature signature = Signature.getInstance("SHA1withECDSA");
		signature.initSign(privateKey);

		signature.update(data);
		return signature.sign();

	}
	
	/**
	 *@see {@link sun.security.mscapi.CPublicKey.CECPublicKey#getEncoded()};
	 */
	public boolean verify(byte[] data, byte[] sign) throws GeneralSecurityException {
		ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		Signature signature = Signature.getInstance("SHA1withECDSA");
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}


}