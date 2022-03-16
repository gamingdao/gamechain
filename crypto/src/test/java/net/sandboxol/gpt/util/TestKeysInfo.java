package net.sandboxol.gpt.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;

public class TestKeysInfo {


	public static void main(String[] args) {
		test1();
	}
	
	static void test1() {
		KeysInfo root = new KeysInfo("ZHENG");
		for(int j=0;j<100;j++) {
			System.out.println(j+":"+System.currentTimeMillis()/1000);
			KeysInfo kh = root.getChild(Integer.toString(j));
			for(int i=0;i<10_000_000;i++) {
				print(kh.getChild(Integer.toString(i)),"0x0000");//"0x000000");
			}
		}		
	}
	
	static void test2() {
		String name= "df6yyf";
		byte[] b= Hash.hmacSha256(name.getBytes(), name.getBytes());
		System.out.println(Numeric.toHexString(b));
		hex2Oct(b);
		System.out.println(Numeric.toHexString(b));
	}


	

	static final void hex2Oct(byte[] hex) {
		for (int i = 0; i < hex.length; i++) {
			hex[i] = (byte)(oct(hex[i]>>4)<<4 | oct(hex[i]));
		}
	}
	
	static final byte oct(int src) {
		//01234567 ->81239567
		int oct = src & 7;
		if (oct == 0 || oct == 4) {
			oct = oct >> 2 | 1 << 3;
		}
		return (byte)oct;
	}

	static void print(KeysInfo ki, String prefix) {
		String addr = Address.from(ki.getPublic());
		if (allIsOct(addr)) {
			System.out.println("All is OctNumber: ");
		} else if (!addr.startsWith(prefix == null ? "0x0" : prefix)) {
			return;
		}
		StringBuilder sb = new StringBuilder(); 
		sb.append("ADDRESS:").append(addr).append(';');
		sb.append("PUBKEY:").append(Numeric.toHexStringWithPrefixSafe(ki.getPublic())).append(';');
		sb.append("PRIKEY:").append(Numeric.toHexStringWithPrefixSafe(ki.getPrivate())).append(';');
		sb.append("QName:").append(ki.getQName()).append(';');
		//sb.append(loopedTimes(ki));
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
	
	static int loopedTimes(KeysInfo ki) {		
		byte[] salt = ki.getName().getBytes();
		byte[] data = ki.getParent().getPrivate().toByteArray();
		BigInteger N =ECConstant.CURVE.getN();
		BigInteger d = ECConstants.ZERO;
		int i=0;
		for(;;) {
			data = Hash.hmacSha256(salt, data);
			d =  Numeric.toBigInt(data);
			i &= -1;
			if(d.compareTo(ECConstants.ZERO)<0||(d.compareTo(N)>0)) {
				d = d.mod(N);
				i|= 1;
				System.out.println("d is out of range:"+d);
			}
			if(KeysInfo.verifyNafWeight(d)){break;}
			i+=2;
		}	
		if(d.compareTo(ki.getPrivate())!=0){
			System.out.println("d is different!!");
		}
		// return new BigInteger(1,Arrays.copyOfRange(hmac, 0, 32));
		return i;		
	}

}
