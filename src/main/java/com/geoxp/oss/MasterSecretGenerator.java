/*
 * Copyright 2012-2013 Mathias Herberts 
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.geoxp.oss;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.encoders.Hex;

public class MasterSecretGenerator {
  /**
   * AES 256 key used to wrap the master secret. It is not intended to protect
   * the secrecy of the master secret but simply to allow for integrity check
   * via the use of AES Key Wrapping.
   */
  private static final byte[] MASTER_SECRET_WRAPPING_KEY = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
  
  public static Map<PGPPublicKey, byte[]> generate(List<PGPPublicKey> keys, int k) throws OSSException {
    //
    // Generate 256 bit secret
    //
    
    SecureRandom sr = CryptoHelper.getSecureRandom();
    
    byte[] secret = new byte[32];
    
    sr.nextBytes(secret);
    
    //
    // Wrap secret with a static AES Wrapping Key so we can check
    // we've correctly recovered the secret on initialization
    //
    
    byte[] wrappedsecret = CryptoHelper.wrapAES(MASTER_SECRET_WRAPPING_KEY, secret);
    
    return generate(keys, k, wrappedsecret);
  }
  
  public static Map<PGPPublicKey, byte[]> generate(List<PGPPublicKey> keys, int k, byte[] wrappedsecret) throws OSSException {
    
    if (null == keys) {
      throw new OSSException("Missing public PGP Public Keys.");
    }
    
    //
    // Make sure each PGP public key can encrypt data
    //
    
    Set<String> nonEncryptionFingerprints = new HashSet<String>();
    
    for (PGPPublicKey key: keys) {
      if (!key.isEncryptionKey()) {
        nonEncryptionFingerprints.add(new String(Hex.encode(key.getFingerprint())));
      }
    }
    
    if (!nonEncryptionFingerprints.isEmpty()) {
      StringBuilder sb = new StringBuilder();
      
      sb.append("PGP Public Keys need to be encryption keys, the following keys were not:");
      
      for (String fpr: nonEncryptionFingerprints) {
        sb.append(" ");
        sb.append(fpr);
      }
      
      throw new OSSException(sb.toString());
    }
    
    //
    // Check value of k
    //
    
    if (k < 1 || k > keys.size()) {
      throw new OSSException("Invalid number of needed shares, was " + k + ", should have been in [1," + keys.size() + "]");
    }
    
    //
    // Split the secret using Shamir Secret Sharing Scheme if k is > 1
    //
    
    Map<PGPPublicKey, byte[]> perkeysecret = new HashMap<PGPPublicKey, byte[]>();
    
    if (k == 1) {
      //
      // Simply encrypt the secret with each public key
      //
      
      for (PGPPublicKey key: keys) {
        try {          
          perkeysecret.put(key, CryptoHelper.encryptPGP(wrappedsecret, key, true, "", PGPCompressedData.ZIP, PGPEncryptedData.AES_256));
        } catch (IOException ioe) {
          throw new OSSException(ioe);
        }               
      }
    } else {
      List<byte[]> secrets = CryptoHelper.SSSSSplit(wrappedsecret, keys.size(), k);
      
      for (int i = 0; i < keys.size(); i++) {
        
        PGPPublicKey key = keys.get(i);
        byte[] share = secrets.get(i);
        
        try {
          perkeysecret.put(key, CryptoHelper.encryptPGP(share, key, true, "", PGPCompressedData.ZIP, PGPEncryptedData.AES_256));
        } catch (IOException ioe) {
          throw new OSSException(ioe);
        }
      }
    }
    
    return perkeysecret;
  }
  
  public static byte[] getMasterSecretWrappingKey() {
    return MASTER_SECRET_WRAPPING_KEY;
  }
}
