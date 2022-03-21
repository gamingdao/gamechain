package net.sandboxol.gpt;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import net.sandboxol.gpt.crypto.JsonTool;
import net.sandboxol.gpt.crypto.KeysTool;
import net.sandboxol.gpt.util.Numeric;

public class TestSignTool {
	
	private static KeysTool kt = new KeysTool("kejun","sandboxol");

	public static void main(String[] args) {
		test1();

	}
	
	static void test1() {
		String str = testJstr();
		JSONObject json = testJson(str);
		byte[] hash = testHash(str);
		json.put("hash", Numeric.toHexString(hash));
		String sign = testSign(hash);
		json.put("sign", sign);		
		String addr = testAddr(hash,sign);
		json.put("addr", addr);		
		verifySign(hash,sign);
		
		str = json.toJSONString();
		System.out.println("new json:"+str);
		
		hash = testHash(str);
		sign = testSign(hash);
		addr = testAddr(hash,sign);
		verifySign(hash,sign);

	}
	
	private static String testJstr() {
		return "{\r\n"
				+ "  \"addr\": \"0xD052340010e8AD9362B65a4c7367aC4E00920e38\","
				+ "  \"sign\": \"0x1c009d21c0b99ca38e8a1c7ec5f2138580a8da19414e723e48f51387c0600e24cb0b1a038f0308e7379ade6d804f56e98d12243af6a906f85686823740e7da7597db\",\r\n"
				+ "  \"siteId\": \"net.sandboxol\","
				+ "  \"userId\": \"harry\" "
				+ "}";
	}
	
	private static JSONObject testJson(String jstr) {
		return JSON.parseObject(jstr);	
	}

	
	static byte[] testHash(String json){
		byte[] hash = JsonTool.hash(json);
		System.out.println("hash:"+Numeric.toHexString(hash));
		return hash;
	}
	
	static String testSign(byte[] hash) {
		String sign = kt.sign(hash,false);
		System.out.println("sign:"+sign);
		return sign;
	}
	
	static String testAddr(byte[] hash, String sign) {
		String addr = KeysTool.getAddress(hash,sign);
		System.out.println("addr:"+addr);
		return addr;
	}

	
	static boolean verifySign(byte[] hash, String sign) {
		boolean b = KeysTool.verify(hash, sign);
		System.out.println("verify:"+b);
		return b;
	}

}
