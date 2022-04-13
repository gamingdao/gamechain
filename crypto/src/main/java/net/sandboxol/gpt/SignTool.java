package net.sandboxol.gpt;

import java.util.Arrays;
import java.util.HashMap;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.hhoss.code.ecc.Address;
import com.hhoss.code.ecc.KeysHolder;
import com.hhoss.code.ecc.KeysNode;
import com.hhoss.code.ecc.Numeric;
import com.hhoss.code.ecc.SignData;
import com.hhoss.code.ecc.SignUtil;
import com.hhoss.hash.Digester;
import com.hhoss.hash.Fields;
import com.hhoss.hash.Hash;


public class SignTool {
	private KeysNode keysNode;
	
	public SignTool(String childName, String groupName) {
		this.keysNode = KeysHolder.get(childName, groupName);
	}
	
	public String getAddress() {
		String addr = Address.from(keysNode.getPublic());
		return Address.toChecksum(addr);
	}

	public static String getAddress(byte[] hash, String sign) {
		return Address.toChecksum(Address.from(hash,sign));
	}
	
	/**
	 * Sign a hash with the private key.
	 * @param hash the hash data need to sign
	 * @return SignatureData with r,s,v
	 */
	public SignData sign(byte[] hash) {
		 return SignUtil.sign(hash,keysNode);
	} 

	/**
	 * SignUtil a message with the private key.
	 *
	 * @param data the data need to sign
	 * @param needHash boolean true will Hash.sha3(data), false if the data NO need hash again
	 * @return An BigInteger[r,s] of the hash
	 */
	public String sign(byte[] data, boolean needHash) {
		byte[] hash = needHash? Hash.sha3(data):data;
		return SignUtil.sign(hash,keysNode).getEtherEncode();
	}
	
	/**
	 * @param hash data hash of sign generated from 
	 * @param sign to be verified 
	 * @return true if the sign match the hash
	 */
	public static boolean verify(byte[] hash, String sign) {
		return SignUtil.verify(hash, sign);
	}
	
	public static boolean verify(String json) {
		JSONObject objJSON = JSON.parseObject(json);//root should be map,not array
		String strSign = objJSON.getString(Fields.SIGN_FIELD);	
		if(strSign==null) {
			System.out.println("missing sign data,can't verify sign.");
			return false;
		}
		
		byte[]  digest = Digester.digest(objJSON);
		String strHash = objJSON.getString(Fields.HASH_FIELD);		
		byte[] digHash = Numeric.hexStringToByteArray(strHash);
		if(!Arrays.equals(digHash,digest)) {
			System.out.println(strHash+" hash is diffrent with real: "+Numeric.toHexString(digest));
			return false;
		}
		if(!verify(digest, strSign)) {
			System.out.println(strSign+" sign is diffrent with real: "+strSign);
			return false;
		}
		
		return true;
	}
	
	public static byte[] hash(String json) {
		Object jobj = JSON.parse(json);			
		return Digester.digest(jobj);
	}
 	
	public static void main(String[] args) throws Exception  {	
		test1();
	}
	private static void test1() {		
		String jo = "{a:[{\"a\":0},{\"b\":32362323233}]}";		
		System.out.println(Numeric.toHexString(hash(jo)));
		String o = "[{a:'0'},{'b':3}]";		
		System.out.println(Numeric.toHexString(hash(o)));

		System.out.println(Numeric.toHexString(Digester.digest(new HashMap<Integer,Integer>(){{put(1,8);put(0,7);}})));
		System.out.println(Numeric.toHexString(hash("[7,8]")));		
	}

}
