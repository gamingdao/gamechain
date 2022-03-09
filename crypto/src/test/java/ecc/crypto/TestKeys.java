package ecc.crypto;

import ecc.util.Hash;
import ecc.util.Numeric;

public class TestKeys {

	public static void main(String[] args) {
		test1();
	}
	private static void test1() {
		ECKeyPair.create("kejun", "zheng");
		ECKeyPair.needCache=false;
		ECKeyPair.keyIsOct=true;
		for(int j=0;j<100;j++) {
			System.out.println(j+":"+System.currentTimeMillis()/1000);
			for(int i=0;i<10_000_000;i++) {
				ECKeyPair.create(i+"."+j, "zheng").print("0x00000");;
			}
		}		
	}
	
	private static void test2() {
		String name= "df6yyf";
		byte[] b= Hash.hmacSha256(name.getBytes(), name.getBytes());
		System.out.println(Numeric.toHexString(b));
		ECKeyPair.hex2Oct(b);
		System.out.println(Numeric.toHexString(b));
	}

}
