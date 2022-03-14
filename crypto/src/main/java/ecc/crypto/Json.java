package ecc.crypto;

import java.util.Arrays;
import java.util.HashMap;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import ecc.util.Digester;
import ecc.util.HashFields;
import ecc.util.Numeric;

public class Json implements HashFields {
	
	public static boolean verify(String json) {
		JSONObject objJSON = JSON.parseObject(json);//root should be map,not array
		String strSign = objJSON.getString(SIGN_FIELD);	
		if(strSign==null) {
			System.out.println("missing sign data,can't verify sign.");
			return false;
		}
		
		byte[]  digest = Digester.digest(objJSON);
		String strHash = objJSON.getString(HASH_FIELD);
		
		byte[] digHash = Numeric.hexStringToByteArray(strHash);
		if(!Arrays.equals(digHash, digest)) {
			System.out.println(strHash+" hash is diffrent with real: "+Numeric.toHexString(digHash));
			return false;
		}
		
		ECKeyPair.verify(digest, strSign);
		if(!ECKeyPair.verify(digest, strSign)) {
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
		String jo = "{a:[{\"a\":0},{\"b\":32362323233}]}";		
		System.out.println(Numeric.toHexString(hash(jo)));
		String o = "[{a:'0'},{'b':3}]";		
		System.out.println(Numeric.toHexString(hash(o)));

		System.out.println(Numeric.toHexString(Digester.digest(new HashMap<Integer,Integer>(){{put(1,8);put(0,7);}})));
		System.out.println(Numeric.toHexString(hash("[7,8]")));		
	}
	

}
