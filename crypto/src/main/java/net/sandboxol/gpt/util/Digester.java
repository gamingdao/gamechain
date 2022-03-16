package net.sandboxol.gpt.util;

import java.lang.reflect.Array;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 
 * @author kejun
 * 
 * digest object, return the hash byte[], needn't serialize
 * not like jwt, it serialize object first and then hmachash256,
 * jwt using:{@link com.fasterxml.jackson.databind.ObjectMapper#writeValueAsBytes(Object)})
 * 
 */
public final class Digester implements ECConstant {
    
    /**
     * @param obj to digest/hash
     * @return byte[] digest/hash of the object 
     * 
     * for Map , using xor for entries. because map in insensible of the order,
     * for collection(like list,set,array), hmac with the index as key, it is sensible of the order
     * for date, using the time milliseconds as long bytes
     * for number, using Primitive bytes
     * for boolean, using byte (0 or 1)
     */
    public static byte[] digest(Object obj) {
    	if(obj==null) {
    		return null;
    	}else if(obj instanceof Map) {
    		return digest((Map<?,?>)obj);
    	}else if(obj instanceof Collection) {
    		return digest((Collection<?>)obj);
    	}else if(obj instanceof String) {
    		return digest(Bytes.from((String)obj));
    	}else if(obj instanceof Number) {
    		return digest(Bytes.from((Number)obj));
    	}else if(obj instanceof Character) {
    		return digest(Bytes.from((Character)obj));
    	}else if(obj instanceof Date) {
    		return digest(Bytes.from((Date)obj));
    	}else if(obj instanceof Boolean) {
    		return digest(Bytes.from((Boolean)obj));
    	}else if(obj instanceof byte[]){
    		return digest((byte[])obj);
    	}else if(obj.getClass().isArray()){
    		//primitive Array can't cast to Object[],need handle
    	    byte[] bytes=null;
       		int len = Array.getLength(obj);
    	    for(int i = 0; i < len; i++) {
    	    	Object el = Array.get(obj, i);
    	    	bytes = Bytes.xor(digest(i,el),bytes);
    	    }
           	return bytes;           	
    	}
    	return digest(obj.toString());//DAte,isPrimitive。。。
    }

    /**
     * Map is insensible with order of entry , we think key has same level with value
     * @param map
     * @return
     */
    public static byte[] digest(Map<?,?> map) {
    	byte[] bytes=null;
    	for(Entry<?,?> ent : map.entrySet()) {
    		bytes = Bytes.xor(digest(ent.getKey(),ent.getValue()),bytes);
    	}    	
       	return bytes;           	
    }
    
    /**
     * Collection is sensible with order of element ;
     * if there is same element, we should ensure they are different hash;
     * @param col
     * @return
     */
   public static byte[] digest(Collection<?> col) {
    	byte[] bytes=null;
    	int i=0;
    	for(Object el : col) {
    		bytes = Bytes.xor(digest(i++,el),bytes);
    	}    	
       	return bytes;           	
    }
    
   /**
    * Array is sensible with order of element 
    * @param arr
    * @return
    */
    public static byte[] digest(Object[] arr){
    	byte[] bytes=null;
    	for(int i=0;i<arr.length;i++) {
    		bytes = Bytes.xor(digest(i,arr[i]),bytes);
    	}
       	return bytes;           	
    }    
     
    public static byte[] digest(byte[] arr) {
       	//System.out.println(Numeric.toHexString(data)+" to hash: "+Numeric.toHexString(hash(HASH,data)));
       	return Hash.hash(arr,HASH);
    }
    
    public static byte[] digest(Object k, Object v) {
    	if(HashFields.ignore(k)){return null;}
		try {
			return Hash.hmac(Bytes.from(k),digest(v),HMAC);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
    } 

	
    public static boolean isEqual(byte[] a, byte[] b) {
    	return MessageDigest.isEqual(a, b);
    }

    public static void main(String[] args) throws Exception {
		System.out.println(Numeric.toHexString(digest(new Object[] {true,'r',5,7L,new Byte[] {13,15,17}})));
		System.out.println(Numeric.toHexString(digest(new Byte[] {3,5,0,7})));
		System.out.println(Numeric.toHexString(digest(new byte[] {3,0,5,7})));
		System.out.println(Numeric.toHexString(digest(new long[] {3236,0,534,6456})));
		System.out.println(Numeric.toHexString(digest(new long[] {3236,534,0,6456})));
		
		System.out.println(Numeric.toHexString(Hash.hmac(new byte[] {3,0,5,7,9,2,5},new byte[] {9,5},HMAC)));
		System.out.println(Numeric.toHexString(Hash.hmac(new byte[] {3,0,5,7,9},new byte[] {2,5,9,5},HMAC)));
	
	}

}