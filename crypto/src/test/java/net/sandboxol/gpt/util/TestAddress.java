package net.sandboxol.gpt.util;

public class TestAddress implements ECConstant{


	public static void main(String[] args) {
		test1();
		test3Key2Addr();
		//test4();
	}
	
	static void test3Key2Addr() {
		//https://xz.aliyun.com/t/2718
		String d = "0x614f5e36cd55ddab0947d1723693fef5456e5bee24738ba90bd33c0c6e68e269";
		String addr = Address.from(new KeysNode("test",d).getPublic());
		System.out.println(addr);
	}
	
	static void test4() {
		String s = "0x00025ddab078394bee24738ba90bd33c0c6e68e269";
		System.out.println(Address.from(Address.from(s)));
		System.out.println(Address.toChecksum(Address.from(s)));
		System.out.println(Address.toChecksum(Address.toChecksum(Address.from(s))));
		
		byte[] bytes = Numeric.toBytesPadded(s,PUBLIC_BITS>>3);
		System.out.println( Address.from(bytes));
		
		bytes = Numeric.hexStringToByteArray(s);
		System.out.println( Address.from(bytes));
		
		bytes = Numeric.hexStringToByteArray0(s);
		System.out.println( Address.from(bytes));
		
		s = "0x000025ddab078394bee24738ba90bd33c0c6e68e269";
		bytes = Numeric.toBytesPadded(s,PUBLIC_BITS>>3);
		System.out.println( Address.from(bytes));
		
		bytes = Numeric.hexStringToByteArray(s);
		System.out.println( Address.from(bytes));
		
		bytes = Numeric.hexStringToByteArray0(s);
		System.out.println( Address.from(bytes));
		

	}
	static void testChecksum(String addr) {
		String s = Address.toChecksum(addr);
		System.out.println(addr.equals(s));
	}
	
	static void test1() {
		testChecksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
		testChecksum("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
		testChecksum("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
		testChecksum("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");		
	}


}
