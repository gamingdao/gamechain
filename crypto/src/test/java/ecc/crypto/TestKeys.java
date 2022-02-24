package ecc.crypto;

public class TestKeys {

	public static void main(String[] args) {
		ECKeyPair.create("kejun", "zheng");
		for(int i=0;i<1000;i++) {
			ECKeyPair.create("ke"+i, "zheng");
		}
	}

}
