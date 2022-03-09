/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package ecc.util;

import java.math.BigInteger;
import java.security.SignatureException;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;

import ecc.crypto.Keys;
import ecc.crypto.Sign;

public interface ECOperations {

	final int CHAIN_ID_INC = 35;
	final int LOWER_REAL_V = 27;
    final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    final ECDomainParameters CURVE = new ECDomainParameters(
                    CURVE_PARAMS.getCurve(),
                    CURVE_PARAMS.getG(),
                    CURVE_PARAMS.getN(),
                    CURVE_PARAMS.getH());
    final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

    Sign.SignatureData getSignatureData();

    byte[] getEncodedTransaction(Long chainId);

    default String getFrom() throws SignatureException {
        byte[] encodedTransaction = getEncodedTransaction(getChainId());
        BigInteger v = Numeric.toBigInt(getSignatureData().getV());
        byte[] r = getSignatureData().getR();
        byte[] s = getSignatureData().getS();
        Sign.SignatureData signatureDataV = new Sign.SignatureData(getRealV(v), r, s);
        BigInteger key = Sign.signedMessageToKey(encodedTransaction, signatureDataV);
        return "0x" + Keys.getAddress(key);
    }

    default void verify(String from) throws SignatureException {
        String actualFrom = getFrom();
        if (!actualFrom.equals(from)) {
            throw new SignatureException("from mismatch");
        }
    }

    default byte getRealV(BigInteger bv) {
        long v = bv.longValue();
        if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
            return (byte) v;
        }
        byte realV = LOWER_REAL_V;
        int inc = 0;
        if ((int) v % 2 == 0) {
            inc = 1;
        }
        return (byte) (realV + inc);
    }

    default Long getChainId() {
        BigInteger bv = Numeric.toBigInt(getSignatureData().getV());
        long v = bv.longValue();
        if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
            return null;
        }
        return (v - CHAIN_ID_INC) / 2;
    }
}
