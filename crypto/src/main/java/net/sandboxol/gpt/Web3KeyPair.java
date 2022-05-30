package net.sandboxol.gpt;

import java.math.BigInteger;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;

import com.hhoss.code.ecc.KeysNode;
import com.hhoss.code.ecc.Numeric;
import com.hhoss.code.ecc.SignData;
import com.hhoss.code.ecc.SignUtil;

public class Web3KeyPair extends ECKeyPair {
  
  private KeysNode keysNode;
  
  public Web3KeyPair(KeysNode kn) {
    super(null,null);
    this.keysNode=kn;
  }
  
  @Override
  public BigInteger getPublicKey() {
    if(keysNode==null) {
      return super.getPublicKey();
    }else{
      return Numeric.toBigInt(keysNode.getPublic());
    }
  }
  
  @Override
  public ECDSASignature sign(byte[] data) {
   SignData sd = SignUtil.sign(data, keysNode);
   return new ECDSASignature(sd.getR(),sd.getS()).toCanonicalised();
  }
  
  @Override
  public boolean equals(Object o) {    
      if (this == o) { return true; }
      if (o == null || getClass() != o.getClass()) { return false;}
      return (keysNode==null)?super.equals(o):keysNode.equals(o);
  }
  
  @Override
  public int hashCode() {
      return (keysNode==null)?super.hashCode():keysNode.hashCode();
  }

   
}
