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

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class OSS {
  
  /**
   * Name of servlet context init parameter containing the token TTL in ms
   */
  public static final String CONTEXT_PARAM_OSS_TOKEN_TTL = "oss.token.ttl";

  /**
   * Name of servlet context init parameter containing the list of SSH keys that can call gensecret
   */
  public static final String CONTEXT_PARAM_OSS_GENSECRET_SSHKEYS = "oss.gensecret.sshkeys";

  /**
   * Name of servlet context init parameter containing the list of SSH keys that can call putsecret
   */
  public static final String CONTEXT_PARAM_OSS_PUTSECRET_SSHKEYS = "oss.putsecret.sshkeys";

  /**
   * Name of servlet context init parameter containing the list of SSH keys that can call init
   */
  public static final String CONTEXT_PARAM_OSS_INIT_SSHKEYS = "oss.init.sshkeys";
  
  /**
   * Directory where secrets are stored
   */
  public static final String CONTEXT_PARAM_OSS_KEYSTORE_DIR = "oss.keystore.dir";
  
  /**
   * AES 256 key used to wrap the master secret. It is not intended to protect
   * the secrecy of the master secret but simply to allow for integrity check
   * via the use of AES Key Wrapping.
   */
  private static final byte[] MASTER_SECRET_WRAPPING_KEY = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
  
  /**
   * This is the master secret used by the instance of Open Secret Server to protect
   * the secrets it manages.
   */
  private static byte[] MASTER_SECRET = null;
  
  /**
   * Public key part of a session RSA key pair.
   * This is a key pair generated at startup time and used
   * to protect data exchanges with the OSS.
   */
  private static RSAPublicKey SESSION_RSA_PUBLIC;
  
  /**
   * Private key part of the session RSA key pair
   */
  private static RSAPrivateKey SESSION_RSA_PRIVATE;
  
  /**
   * Maximum allowed age of received tokens, in ms
   */
  private static long MAX_TOKEN_AGE = 5000L;
  
  /**
   * Set of SSH key fingerprints which can generate new secrets
   */
  private static final Set<String> GENSECRET_AUTHORIZED_SSHKEYS = new HashSet<String>();

  /**
   * Set of SSH key fingerprints which can init the Open Secret Server
   */
  private static final Set<String> INIT_AUTHORIZED_SSHKEYS = new HashSet<String>();

  /**
   * Set of SSH key fingerprints which can store secrets
   */
  private static final Set<String> PUTSECRET_AUTHORIZED_SSHKEYS = new HashSet<String>();
  
  private static KeyStore KEYSTORE;
  
  private static final Set<byte[]> initSecrets = new HashSet<byte[]>();
  
  static {
    //
    // Generate session RSA key pair
    //
    
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    // For explanation of 'certainty', refer to http://bouncy-castle.1462172.n4.nabble.com/Questions-about-RSAKeyGenerationParameters-td1463186.html
    RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("65537"), CryptoHelper.getSecureRandom(), 2048, 64);
    gen.init(params);
    final AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
        
    SESSION_RSA_PRIVATE = new RSAPrivateKey() {
      public BigInteger getModulus() { return ((RSAKeyParameters) keypair.getPrivate()).getModulus(); }
      public String getFormat() { return "PKCS#8"; }
      public byte[] getEncoded() { return null; }
      public String getAlgorithm() { return "RSA"; }
      public BigInteger getPrivateExponent() { return ((RSAKeyParameters) keypair.getPrivate()).getExponent(); }
    };
    
    SESSION_RSA_PUBLIC = new RSAPublicKey() {
      public BigInteger getModulus() { return ((RSAKeyParameters) keypair.getPublic()).getModulus(); }
      public String getFormat() { return "PKCS#8"; }
      public byte[] getEncoded() { return null; }
      public String getAlgorithm() { return "RSA"; }
      public BigInteger getPublicExponent() { return ((RSAKeyParameters) keypair.getPublic()).getExponent(); }
    };    
  }
  
  public static byte[] getMasterSecretWrappingKey() {
    return MASTER_SECRET_WRAPPING_KEY;
  }
  
  public static byte[] getMasterSecret() {
    return MASTER_SECRET;
  }
  
  public static RSAPublicKey getSessionRSAPublicKey() {
    return SESSION_RSA_PUBLIC;
  }
  
  public static RSAPrivateKey getSessionRSAPrivateKey() {
    return SESSION_RSA_PRIVATE;
  }
  
  public static long getMaxTokenAge() {
    return MAX_TOKEN_AGE;
  }
  
  public static void setMaxTokenAge(String ttl) {
    if (null == ttl) {
      return;
    }
    
    MAX_TOKEN_AGE = Long.valueOf(ttl);
  }
  
  public static void setGenSecretSSHKeys(String keylist) {
    setSSHKeys(GENSECRET_AUTHORIZED_SSHKEYS, keylist);
  }
  
  public static void setInitSSHKeys(String keylist) {
    setSSHKeys(INIT_AUTHORIZED_SSHKEYS, keylist);
  }
  
  public static void setPutSecretSSHKeys(String keylist) {
    setSSHKeys(PUTSECRET_AUTHORIZED_SSHKEYS, keylist);
  }
  
  private static void setSSHKeys(Set<String> keyset, String keylist) {
    if (null == keylist) {
      return;
    }
    
    String[] keys = keylist.split(",");
    
    keyset.clear();
    
    for (String key: keys) {
      key = key.toLowerCase().replaceAll("[^0-9a-f]", "");
      
      if (32 == key.length()) {
        keyset.add(key);
      }
    }
  }
  
  public static boolean checkGenSecretSSHKey(byte[] keyblob) {
    return checkSSHKey(GENSECRET_AUTHORIZED_SSHKEYS, keyblob);
  }
  
  public static boolean checkInitSSHKey(byte[] keyblob) {
    return checkSSHKey(INIT_AUTHORIZED_SSHKEYS, keyblob);
  }
  
  public static boolean checkPutSecretSSHKey(byte[] keyblob) {
    return checkSSHKey(PUTSECRET_AUTHORIZED_SSHKEYS, keyblob);
  }
  
  private static boolean checkSSHKey(Set<String> keys, byte[] keyblob) {
    byte[] keyfpr = CryptoHelper.sshKeyBlobFingerprint(keyblob);
    
    String fpr = null;
    
    try {
      fpr = new String(Hex.encode(keyfpr), "UTF-8");
    } catch (UnsupportedEncodingException uee) {
    }
    
    return keys.contains(fpr);
  }
  
  public static void setKeyStoreDirectory(String dir) {
    if (null == dir) {
      return;
    }
    
    KEYSTORE = new DirectoryHierarchyKeyStore(dir);
  }
  
  public static KeyStore getKeyStore() {
    return KEYSTORE;
  }
  
  public static class OSSToken {
    private final long ts;
    private final byte[] secret;
    private final byte[] keyblob;
    
    public OSSToken(long ts, byte[] secret, byte[] keyblob) {
      this.ts = ts;
      this.secret = secret;
      this.keyblob = keyblob;
    }
    
    public long getTs() {
      return ts;
    }
    
    public byte[] getKeyblob() {
      return keyblob;
    }
    
    public byte[] getSecret() {
      return secret;
    }
  }
  
  public static OSSToken checkToken(byte[] token) throws OSSException {
    //
    // Extract token parts
    //
    
    int offset = 0;
    byte[] tsdata = CryptoHelper.decodeNetworkString(token, offset);
    offset += 4 + tsdata.length;        
    byte[] secret = CryptoHelper.decodeNetworkString(token, offset);
    offset += 4 + secret.length;
    byte[] keyblob = CryptoHelper.decodeNetworkString(token, offset);
    offset += 4 + keyblob.length;
    
    int signedlen = offset;
    
    byte[] sigblob = CryptoHelper.decodeNetworkString(token, offset);
    
    //
    // Check token timestamp
    //
    
    long ts = 0;
    
    for (int i = 0; i < 8; i++) {
      ts <<= 8;
      ts |= (tsdata[i] & 0xffL);
    }

    if (System.currentTimeMillis() - ts > OSS.getMaxTokenAge()) {
      throw new OSSException("OSS Token has expired.");
    }
    
    //
    // Verify signature
    //
    
    if (!CryptoHelper.sshSignatureBlobVerify(token, 0, signedlen, sigblob, CryptoHelper.sshKeyBlobToPublicKey(keyblob))) {
      throw new OSSException("Invalid signature of OSS Token.");
    }
    
    return new OSSToken(ts, secret, keyblob);
  }

  /**
   * Add an initialization secret
   * 
   * @param secret
   */
  public static void init(byte[] secret) throws OSSException {
    //
    // Check if the secret was wrapped with the master wrapping key.
    // If so this means the secret is the wrapped master secret.
    //
    
    byte[] clearsecret = CryptoHelper.unwrapAES(MASTER_SECRET_WRAPPING_KEY, secret);
    
    if (null != clearsecret) {
      MASTER_SECRET = clearsecret;
      initSecrets.clear();
      return;
    }
    
    //
    // Otherwise, attempt to recover secret split with Shamir Scheme
    //
    
    initSecrets.add(secret);
    
    byte[] mastersecret = CryptoHelper.SSSSRecover(initSecrets);
    
    if (null == mastersecret) {
      throw new OSSException("Unable to recover master secret.");
    }
    
    //
    // Attempt to unwrap master secret
    //
    
    byte[] sec = CryptoHelper.unwrapAES(MASTER_SECRET_WRAPPING_KEY, mastersecret);
    
    if (null != sec) {
      MASTER_SECRET = sec;
      initSecrets.clear();
      return;
    }
  }
  
  public static boolean isInitialized() {
    return null != MASTER_SECRET;
  }
}
