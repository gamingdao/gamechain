package net.sandboxol.gpt.util;

public class TestKeysHolder {


	public static void main(String[] args) {
		test1();
	}
	
	private static void test1() {
		KeysInfo root = new KeysInfo("ZHENG");
		for(int j=0;j<100;j++) {
			System.out.println(j+":"+System.currentTimeMillis()/1000);
			KeysInfo kh = root.getChild(Integer.toString(j));
			for(int i=0;i<10_000_000;i++) {
				print(kh.getChild(Integer.toString(i)),"0x0");//"0x000000");
			}
		}		
	}
	
	private static void test2() {
		String name= "df6yyf";
		byte[] b= Hash.hmacSha256(name.getBytes(), name.getBytes());
		System.out.println(Numeric.toHexString(b));
		hex2Oct(b);
		System.out.println(Numeric.toHexString(b));
	}


	

	private static final void hex2Oct(byte[] hex) {
		for (int i = 0; i < hex.length; i++) {
			hex[i] = (byte)(oct(hex[i]>>4)<<4 | oct(hex[i]));
		}
	}
	
	private static final byte oct(int src) {
		//01234567 ->81239567
		int oct = src & 7;
		if (oct == 0 || oct == 4) {
			oct = oct >> 2 | 1 << 3;
		}
		return (byte)oct;
	}

	private static void print(KeysInfo ckh, String prefix) {
		String addr = Address.from(ckh.getPublic());
		if (allIsOct(addr)) {
			System.out.println("All is OctNumber: ");
		} else if (!addr.startsWith(prefix == null ? "0x" : prefix)) {
			return;
		}
		StringBuilder sb = new StringBuilder(); 
		sb.append("ADDRESS:").append(addr).append(';');
		sb.append("PUBKEY:").append(Numeric.toHexStringWithPrefixSafe(ckh.getPublic())).append(';');
		sb.append("PRIKEY:").append(Numeric.toHexStringWithPrefixSafe(ckh.getPrivate())).append(';');
		sb.append("QName:").append(ckh.getQName()).append(';');
		System.out.println(sb.toString());
	}

	// 十进制
	private static boolean allIsOct(String str) {
		for (int i = 2, n = str.length(); i < n; i++) {
			char c = str.charAt(i);
			if (c < '0' || c > '9') {
				return false;
			}
		}
		return true;
	}

}
