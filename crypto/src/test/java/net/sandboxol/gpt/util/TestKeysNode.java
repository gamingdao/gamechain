package net.sandboxol.gpt.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;

public class TestKeysNode {


	public static void main(String[] args) {
		//test1(true);
		test2();
	}
	
	static void test1(boolean useOct) {
		KeysNode.useOct=useOct;
		KeysNode root = new KeysNode("Sandbox");
		for(int j=0;j<100;j++) {
			System.out.println(j+":"+System.currentTimeMillis()/1000);
			KeysNode kh = root.getChild(Integer.toString(j));
			for(int i=0;i<1_000_000;i++) {
				print(kh.getChild(Integer.toString(i)),"0x00000");//"0x000000");
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
			System.out.println("All is OctNumber: ");
		} else if (!addr.startsWith(prefix == null ? "0x00" : prefix)) {
			return;
		}
		StringBuilder sb = new StringBuilder(); 
		sb.append("ADDRESS:").append(addr).append(';');
		sb.append("PUBKEY:").append(Numeric.toHexString(ki.getPublic())).append(';');
		sb.append("PRIKEY:").append(Numeric.toHexStringWithPrefixSafe(ki.getPrivate())).append(';');
		sb.append("QName:").append(ki.getQName()).append(';');
		sb.append(loopedTimes(ki));
		System.out.println(sb.toString());
	}

	// 十进制
	static boolean allIsOct(String str) {
		for (int i = 2, n = str.length(); i < n; i++) {
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
