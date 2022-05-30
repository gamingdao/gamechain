package net.sandboxol.gpt;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;

import com.hhoss.code.ecc.Address;
import com.hhoss.code.ecc.KeysHolder;
import com.hhoss.code.ecc.KeysNode;
import com.hhoss.code.ecc.Numeric;

public class Web3Util {

  /**
   * @param kn KeysNode 
   * @return keyPair ECKeyPair
   */
  public static ECKeyPair getKeyPair(KeysNode kn) {
    return new Web3KeyPair(kn);
  }

  /**
   * @param site name of the site channel
   * @return keyPair ECKeyPair
   */
  public static ECKeyPair getSiteKeyPair(String site) {
    return new Web3KeyPair(KeysHolder.get(site,KeysHolder.ROOT));
  }

  /**
   * @param user id/name in the site channel
   * @param site name of the site channel
   * @return keyPair ECKeyPair
   */
  public static ECKeyPair getUserKeyPair(String user, String site) {
    return new Web3KeyPair(KeysHolder.get(user, site));
  }

  /**
   * @param kn KeysNode 
   * @return Credentials
   */
  public static Credentials getCredentials(KeysNode kn) {
    return Credentials.create(getKeyPair(kn));
  }

  /**
   * @param site name of the site channel
   * @return Credentials
   */
  public static Credentials getSiteCredentials(String site) {
    return getCredentials(KeysHolder.get(site,KeysHolder.ROOT));
  }
  

  /**
   * @param user id/name in the site channel
   * @param site name of the site channel
   * @return Credentials
   */
  public static Credentials getUserCredentials(String user, String site) {
    return getCredentials(KeysHolder.get(user, site));
  }

  /**
   * @param address origin address  
   * @param withPrefix true will with '0x',false will remove '0x'
   * @param withCheck true will with checkSum,false will to lower
   * @return String address of the user
   */
  public static String address(String address, boolean withPrefix, boolean withCheck) {
    String lowerCase = Numeric.cleanHexPrefix(address).toLowerCase();
    if(withCheck) {
      return Address.toChecksum(lowerCase);
    }
    if(withPrefix) {
      return Address.withPrefix(address);
    }
    return address;
  }

}
