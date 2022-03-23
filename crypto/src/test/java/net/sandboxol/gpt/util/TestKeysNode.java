package net.sandboxol.gpt.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;

public class TestKeysNode {

	public static void main(String[] args) {
		//test1("_ROOT.SANDBOX",true);
		test2();
	}
	
	static void test1(String rootName,boolean useOct) {
		KeysNode.useOct=useOct;
		KeysNode root = new KeysNode(rootName);
		for(int g=1;g<32;g++){
			System.out.println(g+":"+System.currentTimeMillis()/1000);
			KeysNode kh = root.getChild("G"+g);
			for(int c=1;c<32_000_000;c++) {//32M=42min:"0x0000000"=1/16ppm=1/20min; 1_000_000=78s:"0x000000"=1ppm=1/78s,
				print(kh.getChild("C"+c),"000000");
			}
		}		
	}
	
	static void test2() {
		String name= "df6yyf";
		byte[] b= Hash.hmacSha256(name.getBytes(), name.getBytes());
		System.out.println(Numeric.toHexString(b));
		b=KeysNode.oct(b);
		System.out.println(Numeric.toHexString(b));
	}

	static void print(KeysNode ki, String prefix) {
		String addr = Address.from(ki.getPublic());
		if (allIsOct(addr)) {
			System.out.println("Decimal Number:");
		} else if(addr.startsWith("0000")&&addr.endsWith("0000")){
			System.out.println("HeadTail Zeros:");
		} else {
			if(prefix==null) {prefix="000";}
			if((!addr.startsWith(prefix))&&(!addr.endsWith(prefix))) {
				return;
			}
		}
		StringBuilder sb = new StringBuilder(); 
		sb.append("ADD:").append(Address.toChecksum(addr)).append(';');
		sb.append("PUB:").append(Numeric.toHexString(ki.getPublic())).append(';');
		sb.append("KEY:").append(Numeric.toHexStringPadded(ki.getPrivate(),64,true)).append(';');
		sb.append("QNS:").append(ki.getQName()).append(';');
		sb.append(loopedTimes(ki));
		System.out.println(sb.toString());
	}

	// 十进制
	static boolean allIsOct(String str) {
		for (int i = 0, n = str.length(); i < n; i++) {
			char c = str.charAt(i);
			if (c < '0' || c > '9') {
				return false;
			}
		}
		return true;
	}
	
	static int loopedTimes(KeysNode ki) {		
		byte[] salt = ki.getName().getBytes();
		byte[] data = ki.getParent().getPrivate().toByteArray();
		BigInteger N = ECConstant.CURVE.getN();
		BigInteger d = ECConstants.ZERO;
		int i=0;
		for(;;) {
			data = Hash.hmacSha256(salt, data);
			if(KeysNode.useOct) {
				d =  Numeric.toBigInt(KeysNode.oct(data));
			}else {
				d =  Numeric.toBigInt(data);
				i &= -2;
				if(d.compareTo(ECConstants.ZERO)<0||(d.compareTo(N)>0)) {
					d = d.mod(N);
					i|= 1;
					System.out.println("d is out of range:"+d);
				}
			}
			if(KeysNode.verifyNafWeight(d)){break;}
			i+=2;
		}	
		if(d.compareTo(ki.getPrivate())!=0){
			System.out.println("d is different!!");
		}
		// return new BigInteger(1,Arrays.copyOfRange(hmac, 0, 32));
		return i;		
	}

}
