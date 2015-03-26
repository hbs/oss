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
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.geoxp.oss.client.OSSClient;
import com.geoxp.oss.servlet.GetSecretServlet;

public class OSS {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(OSS.class);  

  /**
   * Default strength for temporary RSA keys
   */
  public static final int DEFAULT_RSA_STRENGTH = 4096;

  /**
   * Size of nonce to append to secrets prior to wrapping them. This is so
   * two identical secrets do not appear as identical secret files after wrapping.
   */
  public static final int NONCE_BYTES = 8;
  
  /**
   * Name of servlet context init parameter containing the maximum secret size in bytes
   */
  public static final String CONTEXT_PARAM_OSS_MAX_SECRET_SIZE = "oss.max.secret.size";

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
   * Name of servlet context init parameter containing the list of SSH keys that can access ACLs
   * If this parameter is set, secure ACLs are used.
   */
  public static final String CONTEXT_PARAM_OSS_ACL_SSHKEYS = "oss.acl.sshkeys";
  
  /**
   * Directory where secrets are stored
   */
  public static final String CONTEXT_PARAM_OSS_KEYSTORE_DIR = "oss.keystore.dir";
  
  /**
   * This is the master secret used by the instance of Open Secret Server to protect
   * the secrets it manages.
   */
  private static ByteBuffer MASTER_SECRET = null;
  
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
   * Maximum size of a secret
   */
  private static int MAX_SECRET_SIZE = 32;
  
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
  
  /**
   * Set of SSH key fingerprints which can access ACLs
   */
  private static final Set<String> ACL_AUTHORIZED_SSHKEYS = new HashSet<String>();
  
  private static KeyStore KEYSTORE;
  
  private static final Set<byte[]> initSecrets = new HashSet<byte[]>();
  
  static {
    //
    // Generate session RSA key pair
    //
    
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    // For explanation of 'certainty', refer to http://bouncy-castle.1462172.n4.nabble.com/Questions-about-RSAKeyGenerationParameters-td1463186.html
    RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("65537"), CryptoHelper.getSecureRandom(), DEFAULT_RSA_STRENGTH, 64);
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

    //
    // Output log line with public key fingerprint
    //

    LOGGER.info("Use '-D" + OSSClient.OSS_RSA + "=" + SESSION_RSA_PUBLIC.getModulus() + ":" + SESSION_RSA_PUBLIC.getPublicExponent() + "' to ensure you're talking to this OSS instance when calling Init/PutSecret/ChangeACL.");
  }
  
  public static byte[] getMasterSecret() {
    byte[] k = new byte[MASTER_SECRET.limit()];
    ByteBuffer bb = MASTER_SECRET.duplicate();
    bb.position(0);
    bb.get(k);
    return k;
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
  
  public static int getMaxSecretSize() {
    return MAX_SECRET_SIZE;
  }
  
  public static void setMaxSecretSize(String size) {
    MAX_SECRET_SIZE = Integer.valueOf(size);
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
  
  public static void setACLSSHKeys(String keylist) {
    setSSHKeys(ACL_AUTHORIZED_SSHKEYS, keylist);
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
  
  public static boolean checkACLSSHKey(byte[] keyblob) {
    return checkSSHKey(ACL_AUTHORIZED_SSHKEYS, keyblob);
  }
  
  public static boolean hasSecureACLs() {
    return !ACL_AUTHORIZED_SSHKEYS.isEmpty();
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
    
    byte[] clearsecret = CryptoHelper.unwrapAES(MasterSecretGenerator.getMasterSecretWrappingKey(), secret);
    
    if (null != clearsecret) {
      MASTER_SECRET = ByteBuffer.allocateDirect(clearsecret.length);
      MASTER_SECRET.put(clearsecret);
      Arrays.fill(clearsecret, (byte) 0); 
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
    
    byte[] sec = CryptoHelper.unwrapAES(MasterSecretGenerator.getMasterSecretWrappingKey(), mastersecret);
    
    if (null != sec) {
      MASTER_SECRET = ByteBuffer.allocateDirect(sec.length);
      MASTER_SECRET.put(sec);
      Arrays.fill(sec, (byte) 0); 
      initSecrets.clear();
      return;
    }
  }
  
  public static boolean isInitialized() {
    return null != MASTER_SECRET;
  }
}
