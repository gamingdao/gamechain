package ecc.crypto;

import static ecc.util.ECOperations.CURVE;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import ecc.util.ECDSASignature;
import ecc.util.Hash;
import ecc.util.Numeric;

/** Elliptic Curve SECP-256k1 generated key pair. */
public class ECKeyPair {
    static final String ROOT="GPT_ROOT";
    private static final Map<String,ECKeyPair > CACHE= new HashMap<>();
    private final ECKeyPair parent;
    private final BigInteger privateKey;
    private final BigInteger publicKey;
    private final String name;

    public ECKeyPair(String name, BigInteger privateKey, BigInteger publicKey, ECKeyPair parent) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.parent=parent;
        this.name=name;
        CACHE.put(getQName(), this);//todo:avoid conflict name
        print();
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
    
    static BigInteger newPrivateKey(String keyName, byte[] seed) {
       // byte[] hmac = Hash.hmacSha512(keyName.getBytes(),seed);
       // return new BigInteger(1,Arrays.copyOfRange(hmac, 0, 32));

        return new BigInteger(1,Hash.hmacSha256(keyName.getBytes(),seed));
    }
 
    /**
     * @return applicaion root Keypair
     */
    public static ECKeyPair createRoot() {
    	ECKeyPair gkp = getCache(ROOT);
    	if(gkp!=null) {return gkp;}
    	BigInteger priKey = newPrivateKey(ROOT,(ROOT+ROOT+ROOT).getBytes());//should from outer
        return new ECKeyPair(ROOT,priKey, publicKeyFromPrivate(priKey),null);
    }
    
    /**
     * for user 
     * @param keyName
     * @param parentName
     * @return
     */
    public static ECKeyPair create(String keyName,String upName) {
    	if(keyName==null){return null;}
    	ECKeyPair root =  createRoot();
    	ECKeyPair parent = (upName==null||ROOT.equalsIgnoreCase(upName))?root:root.create(upName);
        return parent.create(keyName);
    }
     
    ECKeyPair create(String keyName) {
    	if(keyName==null || (parent==null&&!ROOT.endsWith(getName()))){//should initialized; 
    		return null; 
    	}
    	String QName = getQName()+"."+keyName.trim();
    	ECKeyPair gkp = getCache(QName);
    	if(gkp!=null) {return gkp;}
        BigInteger priKey=newPrivateKey(keyName, getPrivateKey().toByteArray());
        BigInteger pubKey=publicKeyFromPrivate(priKey);
        return new ECKeyPair(keyName,priKey, pubKey,this);
    }   
    

    public static ECKeyPair create(String name, KeyPair keyPair) {
        BCECPrivateKey priKey = (BCECPrivateKey) keyPair.getPrivate();
        BCECPublicKey pubKey = (BCECPublicKey) keyPair.getPublic();

        BigInteger privateValue = priKey.getD();

        // Ethereum does not use encoded public keys like bitcoin - see
        // https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm for details
        // Additionally, as the first bit is a constant prefix (0x04) we ignore this value
        byte[] publicBytes = pubKey.getQ().getEncoded(false);
        BigInteger publicValue =  new BigInteger(1, Arrays.copyOfRange(publicBytes, 1, publicBytes.length));

        return new ECKeyPair(name, privateValue, publicValue,null);
    }

    
    private static ECKeyPair getCache(String name) {
    	return CACHE.containsKey(ROOT)?CACHE.get(name):null;
    }
    
    public String getQName() {
        return (parent==null||parent.getName()==null)?getName():(parent.getQName()+"."+getName());
    }
    public String getName() {
    	return name==null||name.isBlank()?null:name.trim();
    }
    
    private void print() {
        System.out.print("ADDRESS:"+getAddress());
        System.out.print(";PUBKEY:"+Numeric.toHexStringWithPrefixSafe(getPublicKey()));
        System.out.print(";PRIKEY:"+Numeric.toHexStringWithPrefixSafe(getPrivateKey()));
        System.out.println(";QName:"+getQName());
    }

    /**
     * Sign a hash with the private key of this key pair.
     *
     * @param hash the transactionHash to sign
     * @return An {@link ECDSASignature} of the hash
     */
    public ECDSASignature sign(byte[] hash) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));

        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(getPrivateKey(), CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(hash);

        return new ECDSASignature(components[0], components[1]).toCanonicalised();
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
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than the group
         * order, but that could change in future versions.
         */
        if (privKey.bitLength() > CURVE.getN().bitLength()) {
            privKey = privKey.mod(CURVE.getN());
        }
        return new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
    }
 
}
