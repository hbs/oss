package com.geoxp.oss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.Hex;

import com.etsy.net.JUDS;
import com.etsy.net.UnixDomainSocketClient;

/**
 * Helper class containing various methods used to
 * ease up cryptographic operations
 */
public class CryptoHelper {
  
  /**
   * Default algorithm to use when generating signatures
   */
  public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256WithRSA";
  
  private static final String SSH_DSS_PREFIX = "ssh-dss";
  private static final String SSH_RSA_PREFIX = "ssh-rsa";
  
  /**
   * SecureRandom used by the class
   */
  private static SecureRandom sr = null;
  
  static {
    //
    // Add BouncyCastleProvider
    //

    Security.addProvider(new BouncyCastleProvider());
    
    //
    // Create PRNG, will be null if provider/algorithm not found
    //
    
    try {
      sr = SecureRandom.getInstance("SHA1PRNG","SUN");
    } catch (NoSuchProviderException nspe) {
    } catch (NoSuchAlgorithmException nsae) {      
    }
  }

  public static SecureRandom getSecureRandom() {
    return CryptoHelper.sr;
  }
  
  /**
   * Pad data using PKCS7.
   * 
   * @param alignment Alignement on which to pad, e.g. 8
   * @param data Data to pad
   * @return The padded data
   */
  public static byte[] padPKCS7(int alignment, byte[] data) {

    //
    // Allocate the target byte array. Its size is a multiple of 'alignment'.
    // If data to pad is a multiple of 'alignment', the target array will be
    // 'alignment' bytes longer than the data to pad.
    //
    
    byte[] target = new byte[data.length + (alignment - data.length % alignment)];
    
    //
    // Copy the data to pad into the target array
    //
          
    System.arraycopy (data, 0, target, 0, data.length);
      
    //
    // Add padding bytes
    //
      
    PKCS7Padding padding = new PKCS7Padding();
      
    padding.addPadding(target, data.length);
                      
    return target;
  }

  /**
   * Remove PKCS7 padding from padded data
   * @param padded The padded data to 'unpad'
   * @return The original unpadded data
   * @throws InvalidCipherTextException if data is not correctly padded
   */
  public static byte[] unpadPKCS7(byte[] padded) throws InvalidCipherTextException {
    PKCS7Padding padding = new PKCS7Padding();
    
    //
    // Determine length of padding
    //
    
    int pad = padding.padCount(padded);
    
    //
    // Allocate array for unpadded data
    //
    
    byte[] unpadded = new byte[padded.length - pad];
    
    //
    // Copy data without the padding
    //
    
    System.arraycopy(padded, 0, unpadded, 0, padded.length - pad);
    
    return unpadded;
  }
  
  /**
   * Protect some data using AES Key Wrapping
   * 
   * @param key AES wrapping key
   * @param data Data to wrap
   * @return The wrapped data
   */
  public static byte[] wrapAES(byte[] key, byte[] data) {
    
    //
    // Initialize AES Wrap Engine for wrapping
    //
    
    AESWrapEngine aes = new AESWrapEngine();
    KeyParameter keyparam = new KeyParameter(key);
    aes.init(true, keyparam);

    //
    // Pad the data on an 8 bytes boundary
    //
    
    byte[] padded = padPKCS7(8, data);
    
    //
    // Wrap data and return it
    //
    
    return aes.wrap(padded, 0, padded.length);
  }
  
  /**
   * Unwrap data protected by AES Key Wrapping
   * 
   * @param key Key used to wrap the data
   * @param data Wrapped data
   * @return The unwrapped data or null if an error occurred
   */
  public static byte[] unwrapAES(byte[] key, byte[] data) {
    
    //
    // Initialize the AES Wrap Engine for unwrapping
    //
    
    AESWrapEngine aes = new AESWrapEngine();
    KeyParameter keyparam = new KeyParameter(key);
    aes.init(false, keyparam);

    //
    // Unwrap then unpad data
    //
    
    try {
      return unpadPKCS7(aes.unwrap(data, 0, data.length));
    } catch (InvalidCipherTextException icte) {
      return null;
    }
  }
  
  /**
   * Encrypt data using RSA.
   * CAUTION: this can take a while on large data
   * 
   * @param key RSA key to use for encryption
   * @param data Cleartext data
   * @return The ciphertext data or null if an error occured
   */  
  public static byte[] encryptRSA(Key key, byte[] data) {
    //
    // Get an RSA Cipher instance
    //
    Cipher rsa = null;
            
    try {
      rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
      rsa.init (Cipher.ENCRYPT_MODE, key, CryptoHelper.sr);                   
      return rsa.doFinal(data);
    } catch (NoSuchProviderException nspe) {
      return null;
    } catch (NoSuchPaddingException nspe) {
      return null;
    } catch (NoSuchAlgorithmException nsae) {
      return null;
    } catch (InvalidKeyException ike) {
      return null;
    } catch (BadPaddingException bpe) {
      return null;
    } catch (IllegalBlockSizeException ibse) {
      return null;
    }
  }
  
  
  /**
   * Decrypt data previously encrypted with RSA
   * @param key RSA key to use for decryption
   * @param data Ciphertext data
   * @return The cleartext data or null if an error occurred
   */
  public static byte[] decryptRSA(Key key, byte[] data) {
    //
    // Get an RSA Cipher instance
    //

    Cipher rsa = null;

    try {
      rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
      rsa.init (Cipher.DECRYPT_MODE, key, CryptoHelper.sr);

      return rsa.doFinal(data);
    } catch (NoSuchProviderException nspe) {
      return null;
    } catch (NoSuchPaddingException nspe) {
      return null;
    } catch (NoSuchAlgorithmException nsae) {
      return null;
    } catch (InvalidKeyException ike) {
      return null;
    } catch (BadPaddingException bpe) {
      return null;
    } catch (IllegalBlockSizeException ibse) {
      return null;
    }    
  }
  
  /**
   * Sign data using the given algorithm
   * 
   * @param algorithm Name of algorithm to use for signing
   * @param key Private key to use for signing (must be compatible with chosen algorithm)
   * @param data Data to sign
   * @return The signature of data or null if an error occurred
   */
  public static byte[] sign(String algorithm, PrivateKey key, byte[] data) {
    try {
      Signature signature = Signature.getInstance(algorithm, "BC");
      signature.initSign(key, CryptoHelper.sr);
      signature.update(data);
      return signature.sign();
    } catch (SignatureException se) { 
      return null;
    } catch (InvalidKeyException ike) {
      return null;
    } catch (NoSuchAlgorithmException nsae) {
      return null;
    } catch (NoSuchProviderException nspe) {
      return null;
    }
  }
  
  /**
   * Verify a signature
   * 
   * @param algorithm Algorithm used to generate the signature
   * @param key Public key to use for verifying the signature
   * @param data Data whose signature must be verified
   * @param sig The signature to verify
   * @return true or false depending on successful verification
   */
  public static boolean verify(String algorithm, PublicKey key, byte[] data, byte[] sig) {
    try {
      Signature signature = Signature.getInstance(algorithm, "BC");
      signature.initVerify(key);
      signature.update(data);
      return signature.verify(sig);
    } catch (SignatureException se) { 
      return false;
    } catch (InvalidKeyException ike) {
      return false;
    } catch (NoSuchAlgorithmException nsae) {
      return false;
    } catch (NoSuchProviderException nspe) {
      return false;
    }    
  }
  
  /**
   * Convert an SSH Key Blob to a Public Key
   * 
   * @param blob SSH Key Blob
   * @return The extracted public key or null if an error occurred
   */
  public static PublicKey sshKeyBlobToPublicKey(byte[] blob) {
    //
    // RFC 4253 describes keys as either
    //
    // ssh-dss p q g y
    // ssh-rsa e n
    //
    
    //
    // Extract SSH key type
    //
    
    byte[] keyType = decodeNetworkString(blob,0);
    int offset = 4 + keyType.length;
    
    String keyTypeStr = new String(keyType);
    
    try {
      if (SSH_DSS_PREFIX.equals(keyTypeStr)) {
        //
        // Extract DSA key parameters p q g and y
        //
        
        byte[] p = decodeNetworkString(blob, offset);
        offset += 4;
        offset += p.length;

        byte[] q = decodeNetworkString(blob, offset);
        offset += 4;
        offset += q.length;

        byte[] g = decodeNetworkString(blob, offset);
        offset += 4;
        offset += g.length;

        byte[] y = decodeNetworkString(blob, offset);
        offset += 4;
        offset += y.length;

        KeySpec key = new DSAPublicKeySpec(new BigInteger(y), new BigInteger(p), new BigInteger(q), new BigInteger(g));
        return KeyFactory.getInstance("DSA").generatePublic(key);
      } else if (SSH_RSA_PREFIX.equals(keyTypeStr)) {
        //
        // Extract RSA key parameters e and n
        //

        byte[] e = decodeNetworkString(blob, offset);
        offset += 4;
        offset += e.length;

        byte[] n = decodeNetworkString(blob, offset);
        offset += 4;
        offset += n.length;

        KeySpec key = new RSAPublicKeySpec(new BigInteger(n), new BigInteger(e));
        return KeyFactory.getInstance("RSA").generatePublic(key);
      } else {
        return null;
      }      
    } catch (NoSuchAlgorithmException nsae) {
      nsae.printStackTrace();
      return null;
    } catch (InvalidKeySpecException ikse) {
      ikse.printStackTrace();
      return null;
    }
  }
  
  /**
   * Compute the MD5 fingerprint of an SSH key blob
   *
   * @param blob Public Key Blob to compute the fingerprint on
   * @return The computed signature or null if an error occurred
   */
  public static byte[] sshKeyBlobFingerprint(byte[] blob) {
    try {
      MessageDigest md5 = MessageDigest.getInstance("MD5");
      md5.update(blob);
      return md5.digest();
    } catch (NoSuchAlgorithmException nsae) {
      return null;
    }
  }

  /**
   * Encode a public key as an SSH Key Blob
   * 
   * @param key Public key to encode
   * @return The encoded public key or null if provided key is not RSA or DSA
   */
  public static byte[] sshKeyBlobFromPublicKey(PublicKey key) {
    
    if (key instanceof RSAPublicKey) {
      
      //
      // Extract public exponent and modulus
      //
      
      BigInteger e = ((RSAPublicKey) key).getPublicExponent();
      BigInteger n = ((RSAPublicKey) key).getModulus();
      
      //
      // Encode parameters as Network Strings
      //
      
      byte[] tns = encodeNetworkString(SSH_RSA_PREFIX.getBytes());
      byte[] ens = encodeNetworkString(e.toByteArray());
      byte[] nns = encodeNetworkString(n.toByteArray());
      
      //
      // Allocate array for blob
      //
      
      byte[] blob = new byte[tns.length + nns.length + ens.length];
      
      //
      // Copy network strings to blob
      //
      
      System.arraycopy(tns, 0, blob, 0, tns.length);
      System.arraycopy(ens, 0, blob, tns.length, ens.length);
      System.arraycopy(nns, 0, blob, tns.length + ens.length, nns.length);
      
      return blob;
    } else if (key instanceof DSAPublicKey) {
      
      //
      // Extract key parameters
      //
      
      BigInteger p = ((DSAPublicKey) key).getParams().getP();
      BigInteger q = ((DSAPublicKey) key).getParams().getQ();
      BigInteger g = ((DSAPublicKey) key).getParams().getG();
      BigInteger y = ((DSAPublicKey) key).getY();
      
      //
      // Encode parameters as network strings
      //
      
      byte[] tns = encodeNetworkString(SSH_DSS_PREFIX.getBytes());
      byte[] pns = encodeNetworkString(p.toByteArray());
      byte[] qns = encodeNetworkString(q.toByteArray());
      byte[] gns = encodeNetworkString(g.toByteArray());
      byte[] yns = encodeNetworkString(y.toByteArray());
      
      //
      // Allocate array for blob
      //
      
      byte[] blob = new byte[tns.length + pns.length + qns.length + gns.length + yns.length];
      
      //
      // Copy network strings to blob
      //
      
      System.arraycopy(tns, 0, blob, 0, tns.length);
      System.arraycopy(pns, 0, blob, tns.length, pns.length);
      System.arraycopy(qns, 0, blob, tns.length + pns.length, qns.length);
      System.arraycopy(gns, 0, blob, tns.length + pns.length + qns.length, gns.length);
      System.arraycopy(yns, 0, blob, tns.length + pns.length + qns.length + gns.length, yns.length);
      
      return blob;
    } else {
      return null;    
    }
    
  }

  /**
   * Generate an SSH signature blob
   * 
   * @param data Data to sign
   * @param key Private key to use for signing
   * @return The generated signature blob or null if the provided key is not supported
   */
  public static byte[] sshSignatureBlobSign(byte[] data, PrivateKey key) {
    
    try {
      if (key instanceof RSAPrivateKey) {
        //
        // Create Signature object
        //
        
        Signature signature = java.security.Signature.getInstance("SHA1withRSA");        
        signature.initSign(key);
        
        signature.update(data);
        
        byte[] sig = signature.sign();
        
        //
        // Build the SSH sigBlob
        //
        
        byte[] tns = encodeNetworkString(SSH_RSA_PREFIX.getBytes());
        byte[] sns = encodeNetworkString(sig);
        
        byte[] blob = new byte[tns.length + sns.length];
        
        System.arraycopy(tns, 0, blob, 0, tns.length);
        System.arraycopy(sns, 0, blob, tns.length, sns.length);
        
        return blob;
      } else if (key instanceof DSAPrivateKey) {
        
        //
        // Create Signature object
        //
        
        Signature signature = java.security.Signature.getInstance("SHA1withDSA");
        signature.initSign(key);
        
        signature.update(data);
        
        byte[] asn1sig = signature.sign();
        
        //
        // Convert ASN.1 signature to SSH signature blob
        // Inspired by OpenSSH code
        //
        
        int frst = asn1sig[3] - (byte) 0x14;
        int scnd = asn1sig[1] - (byte) 0x2c - frst;
        
        byte[] sshsig = new byte[asn1sig.length - frst - scnd - 6];
        
        System.arraycopy(asn1sig, 4 + frst, sshsig, 0, 20);
        System.arraycopy(asn1sig, 6 + asn1sig[3] + scnd, sshsig, 20, 20);

        byte[] tns = encodeNetworkString(SSH_DSS_PREFIX.getBytes());
        byte[] sns = encodeNetworkString(sshsig);
        
        byte[] blob = new byte[tns.length + sns.length];
        System.arraycopy(tns, 0, blob, 0, tns.length);
        System.arraycopy(sns, 0, blob, tns.length, sns.length);
        
        return blob;
      } else {
        return null;
      }      
    } catch (NoSuchAlgorithmException nsae) {
      return null;
    } catch (InvalidKeyException ike) {
      return null;
    } catch (SignatureException se) {
      return null;
    }
  }

  /**
   * Verify the signature included in an SSH signature blob
   *
   * @param data The data whose signature must be verified
   * @param off Offset in the data array
   * @param len Length of data to sign
   * @param sigBlob The SSH signature blob containing the signature
   * @param pubkey The public key to use to verify the signature
   * @return true if the signature was verified successfully, false in all other cases (including if an error occurs).
   */
  public static boolean sshSignatureBlobVerify(byte[] data, int off, int len, byte[] sigBlob, PublicKey pubkey) {
    
    Signature signature = null;
    
    int offset = 0;
    byte[] sigType = decodeNetworkString(sigBlob, 0);
    
    offset += 4;
    offset += sigType.length;
    
    String sigTypeStr = new String(sigType);
    
    try {
      if (pubkey instanceof RSAPublicKey && SSH_RSA_PREFIX.equals(sigTypeStr)) {
        //
        // Create Signature object
        //
        
        signature = java.security.Signature.getInstance("SHA1withRSA");
        signature.initVerify(pubkey);
        
        signature.update(data, off, len);

        byte[] sig = decodeNetworkString(sigBlob, offset);
        
        return signature.verify(sig);
      } else if (pubkey instanceof DSAPublicKey && SSH_DSS_PREFIX.equals(sigTypeStr)) {
        //
        // Create Signature object
        //
        
        signature = java.security.Signature.getInstance("SHA1withDSA");
        signature.initVerify(pubkey);
        
        signature.update(data, off, len);
        
        //
        // Convert SSH signature blob to ASN.1 signature
        //
        
        byte[] rs = decodeNetworkString(sigBlob, offset);
        
        // ASN.1
        int frst = ((rs[0] & 0x80) != 0 ? 1 : 0);
        int scnd = ((rs[20] & 0x80) != 0 ? 1 : 0);

        int length = rs.length + 6 + frst + scnd;
        
        byte[] asn1sig = new byte[length];
        
        asn1sig[0] = (byte) 0x30;
        asn1sig[1] = (byte) 0x2c; 
        asn1sig[1] += frst;
        asn1sig[1] += scnd;
        asn1sig[2] = (byte) 0x02;
        asn1sig[3] = (byte) 0x14;
        asn1sig[3] += frst;
        
        System.arraycopy(rs, 0, asn1sig, 4 + frst, 20);
        
        asn1sig[4 + asn1sig[3]] = (byte) 0x02;
        asn1sig[5 + asn1sig[3]] = (byte) 0x14;
        asn1sig[5 + asn1sig[3]] += scnd;
        
        System.arraycopy(rs, 20, asn1sig, 6 + asn1sig[3] + scnd, 20);
        
        //
        // Verify signature
        //
        return signature.verify(asn1sig);
      } else {
        return false;
      }      
    } catch (NoSuchAlgorithmException nsae) {
      return false;
    } catch (SignatureException se) {
      return false;
    } catch (InvalidKeyException ike) {
      return false;
    }
  }

  public static boolean sshSignatureBlobVerify(byte[] data, byte[] sigBlob, PublicKey pubkey) {
    return sshSignatureBlobVerify(data, 0, data.length, sigBlob, pubkey);
  }
  
  /**
   * Extract an encoded Network String
   * A Network String has its length on 4 bytes (MSB first).
   * 
   * @param data Data to parse
   * @param offset Offset at which the network string starts.
   * @return
   */
  public static byte[] decodeNetworkString(byte[] data, int offset) {
    
    int len = unpackInt(data, offset);
    
    //
    // Safety net, don't allow to allocate more than
    // what's left in the array
    //
    
    if (len > data.length - offset - 4) {
      return null;
    }
    
    byte[] string = new byte[len];
    System.arraycopy(data, offset + 4, string, 0, len);
    
    return string;
  }
  
  /**
   * Encode data as a Network String
   * A Network String has its length on 4 bytes (MSB first).
   * 
   * @param data Data to encode
   * @return the encoded data
   */
  public static byte[] encodeNetworkString(byte[] data) {
    
    byte[] ns = new byte[4 + data.length];
   
    //
    // Pack data length
    //
    
    packInt(data.length, ns, 0);
    
    System.arraycopy(data, 0, ns, 4, data.length);
    
    return ns;
  }
  
  /**
   * Pack an integer value in a byte array, MSB first
   * 
   * @param value Value to pack
   * @param data Byte array where to pack
   * @param offset Offset where to start
   */
  private static void packInt(int value, byte[] data, int offset) {
    data[0] = (byte) ((value >> 24) & 0x000000ff);
    data[1] = (byte) ((value >> 16) & 0x000000ff);
    data[2] = (byte) ((value >> 8) & 0x000000ff);
    data[3] = (byte) (value & 0x000000ff);
  }
  
  /**
   * Unpack an int stored as MSB first in a byte array
   * @param data Array from which to extract the int
   * @param offset Offset in the array where the int is stored
   * @return
   */
  private static int unpackInt(byte[] data, int offset) {
    int value = 0;
    value |= (data[offset] << 24) & 0xff000000;
    value |= (data[offset + 1] << 16) &0x00ff0000;
    value |= (data[offset + 2] << 8) &0x0000ff00;
    value |= data[offset + 3] &0x000000ff;
    
    return value;
  }
  
  public static class SSHAgentClient {
    
    //
    // Request / Response codes from OpenSSH implementation
    // Some are not supported (yet) by this implementation
    //

    //private static final int AGENTC_REQUEST_RSA_IDENTITIES = 1;
    //private static final int AGENT_RSA_IDENTITIES_ANSWER   = 2;
    private static final int AGENT_FAILURE                 = 5;
    private static final int AGENT_SUCCESS                 = 6;

    //private static final int AGENTC_REMOVE_RSA_IDENTITY       = 8;
    //private static final int AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;

    private static final int AGENTC_REQUEST_IDENTITIES    = 11;
    private static final int AGENT_IDENTITIES_ANSWER      = 12;
    private static final int AGENTC_SIGN_REQUEST          = 13;
    private static final int AGENT_SIGN_RESPONSE          = 14;
    //private static final int AGENTC_ADD_IDENTITY          = 17;
    //private static final int AGENTC_REMOVE_IDENTITY       = 18;
    //private static final int AGENTC_REMOVE_ALL_IDENTITIES = 19;

    private UnixDomainSocketClient socket = null;
    
    private ByteArrayOutputStream buffer = null;

    /**
     * Callback interface to handle agent response
     */
    private static interface AgentCallback {
      public Object onSuccess(byte[] packet);
      public Object onFailure(byte[] packet);    
    }
    
    public static class SSHKey {
      public byte[] blob;
      public String comment;
      public String fingerprint;
      
      public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(fingerprint);
        sb.append(" ");
        sb.append(comment);
        return sb.toString();
      }
    }
    
    /**
     * Create an instance of SSHAgentClient using the Unix Socket defined in
     * the environment variable SSH_AUTH_SOCK as set by ssh-agent
     * 
     * @throws IOException in case of errors
     */
    public SSHAgentClient() throws IOException {
      this(System.getenv("SSH_AUTH_SOCK"));
    }
    
    /**
     * Create an instance of SSHAgentClient using the provided Unix Socket
     * 
     * @param path Path to the Unix domain socket to use.
     * @throws IOException In case of errors
     */
    public SSHAgentClient(String path) throws IOException {
      //
      // Connect to the local socket of the SSH agent
      //
    
      socket = new UnixDomainSocketClient(path, JUDS.SOCK_STREAM);
      
      //
      // Create an input buffer for data exchange with the socket
      //
      
      buffer = new ByteArrayOutputStream();        
    }
    
    public void close() {
      socket.close();
    }
    
    /**
     * Send a request to the SSH Agent
     * 
     * @param type Type of request to send
     * @param data Data packet of the request
     * @throws IOException in case of errors
     */
    private void sendRequest(int type, byte[] data) throws IOException {
      
      //
      // Allocate request packet.
      // It needs to hold the request data, the data length
      // and the request type.
      //
      
      byte[] packet = new byte[data.length + 4 + 1];
      
      //
      // Pack data length + 1 (request type)
      //
      
      packInt(data.length + 1, packet, 0);
      
      //
      // Store request type
      //
      
      packet[4] = (byte) type;
      
      //
      // Copy request data
      //
      
      System.arraycopy(data, 0, packet, 5, data.length);
      
      //
      // Write request packet onto the socket
      //
      
      socket.getOutputStream().write(packet);
      socket.getOutputStream().flush();
    }
       
    /**
     * Listen to agent response and call the appropriate method
     * of the provided callback.
     * 
     * @param callback
     * @return
     * @throws IOException
     */
    private Object awaitResponse(AgentCallback callback) throws IOException {
      
      int packetLen = -1;
      
      byte[] buf = new byte[128];
          
      while(true) {
        
        int len = socket.getInputStream().read(buf);
        
        //
        // Add data to buffer
        //
        
        if (len > 0) {
          buffer.write(buf, 0, len);
        }
        
        //
        // If buffer contains less than 4 bytes, continue reading data
        //
        
        if (buffer.size() <= 4) {
          continue;
        }
        
        //
        // If packet len has not yet been extracted, read it.
        //
        
        if (packetLen < 0) {
          packetLen = unpackInt(buffer.toByteArray(), 0);        
        }
        
        //
        // If buffer does not the full packet yet, continue reading
        //
        
        if (buffer.size() < 4 + packetLen) {
          continue;
        }
        
        //
        // Buffer contains the packet data,
        // convert input buffer to byte array
        //
        
        byte[] inbuf = buffer.toByteArray();

        //
        // Extract packet data
        //
        
        byte[] packet = new byte[packetLen];
        System.arraycopy(inbuf, 4, packet, 0, packetLen);
        
        //
        // Put extraneous data at the beginning of 'buffer'
        //
        
        buffer.reset();
        buffer.write(inbuf, 4 + packetLen, inbuf.length - packetLen - 4);
        
        //
        // Extract response type
        //
        
        int respType = packet[0];
        
        if (AGENT_FAILURE == respType) {
          return callback.onFailure(packet);
        } else if (AGENT_SUCCESS == respType) {
          return callback.onSuccess(new byte[0]);
        } else {
          return callback.onSuccess(packet);
        }
      }
    }

    /**
     * Request the agent to sign 'data' using the provided key blob
     * 
     * @param keyblob SSH Key Blob
     * @param data Data to sign
     * @return An SSH signature blob
     */
    public byte[] sign(byte[] keyblob, byte[] data) throws IOException {
      
      //
      // Create request packet
      //
      
      ByteArrayOutputStream request = new ByteArrayOutputStream();
      
      request.write(encodeNetworkString(keyblob));
      request.write(encodeNetworkString(data));
      request.write(new byte[4]);
      
      sendRequest(AGENTC_SIGN_REQUEST, request.toByteArray());
      
      return (byte[]) awaitResponse(new AgentCallback() {
        @Override
        public Object onFailure(byte[] packet) {
          return null;
        }
        @Override
        public Object onSuccess(byte[] packet) {
          if (AGENT_SIGN_RESPONSE != packet[0]) {
            return null;
          }
          
          byte[] signature = decodeNetworkString(packet, 1);
          return signature;
        }
      });
    }

    public List<SSHKey> requestIdentities() throws IOException {
      sendRequest(AGENTC_REQUEST_IDENTITIES, new byte[0]);
      
      Object result = awaitResponse(new AgentCallback() {
        @Override
        public Object onFailure(byte[] packet) {
          return null;
        }
        
        @Override
        public Object onSuccess(byte[] packet) {
          
          if (AGENT_IDENTITIES_ANSWER != packet[0]) {
            return null;
          }
          
          List<SSHKey> keys = new ArrayList<SSHKey>();
          
          int offset = 1;
          
          int numKeys = unpackInt(packet, offset);        
          offset += 4;
          
          for (int i = 0; i < numKeys; i++) {
      
            SSHKey key = new SSHKey();
            
            //
            // Extract key blob
            //
            
            key.blob = decodeNetworkString(packet, offset);
            offset += 4 + key.blob.length;
            
            //
            // Extract comment
            //
            
            byte[] comment = decodeNetworkString(packet, offset);
            key.comment = new String(comment);
            offset += 4 + comment.length;
            
            //
            // Compute key fingerprint
            //
            
            try {
              key.fingerprint = new String(Hex.encode(sshKeyBlobFingerprint(key.blob)), "UTF-8");
            } catch (UnsupportedEncodingException uee) {              
            }

            keys.add(key);
          }
          
          return keys;
        }
      });
      
      return (List<SSHKey>) result;
    }
  }
  
  //
  // Shamir Secret Sharing Scheme
  // The following code is inspired by a java version of Tontine
  //
  
  /**
   * Abstract class representing a number
   */
  private static abstract class SSSSNumber extends Number {
    public abstract SSSSNumber add(SSSSNumber b);  
    public abstract SSSSNumber sub(SSSSNumber b);
    public abstract SSSSNumber mul(SSSSNumber b);
    public abstract SSSSNumber div(SSSSNumber b);
    public abstract SSSSNumber neg();
    public abstract SSSSNumber zero();
    public abstract SSSSNumber one();
    public abstract SSSSNumber clone();
  }

  /**
   * Subclass of SSSSNumber for integer type
   */
  private static final class SSSSInt extends SSSSNumber {
    private int value;
    
    public SSSSInt(int v) {
      value = v;
    }
    
    public SSSSNumber add(SSSSNumber b) {
      if (b instanceof SSSSInt) {
        SSSSInt bInt = (SSSSInt) b;
        return new SSSSInt(value + bInt.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }
  
    public SSSSNumber sub(SSSSNumber b) {
      if (b instanceof SSSSInt) {
        SSSSInt bInt = (SSSSInt) b;
        return new SSSSInt(value - bInt.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    public SSSSNumber mul(SSSSNumber b) {
      if (b instanceof SSSSInt) {
        SSSSInt bInt = (SSSSInt) b;
        return new SSSSInt(value * bInt.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    public SSSSNumber div(SSSSNumber b) {
      if (b instanceof SSSSInt) {
        SSSSInt bInt = (SSSSInt) b;
        return new SSSSInt(value / bInt.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    public SSSSNumber neg() {
      return new SSSSInt(-value);
    }
    
    public SSSSNumber zero() {
      return new SSSSInt(0);
    }
    
    public SSSSNumber one()  {
      return new SSSSInt(1);
    }
    
    public int intValue() {
      return (int) value;
    }
    
    public long longValue() {
      return (long) value;
    }
    
    public float floatValue() {
      return (float) value;
    }
    
    public double doubleValue() {
      return (double) value;
    }
    
    public boolean equals(Object o) {
      if (o instanceof SSSSInt) {
        return (value == ((SSSSInt) o).value);
      } else {
        return false;
      }
    }

    public String toString() {
      return Integer.toString(value);
    }
    
    public SSSSInt clone() {
      return new SSSSInt(this.intValue());
    }
  }

  /**
   * Subclass of SSSSNumber for double types
   */
  private static final class SSSSDouble extends SSSSNumber {
    private double value;

    public SSSSDouble(double v) {
      this.value = v;
    }
  
    public SSSSNumber add(SSSSNumber b) {
      if (b instanceof SSSSDouble) {
        SSSSDouble bDouble = (SSSSDouble) b;
        return new SSSSDouble(value + bDouble.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }
  
    public SSSSNumber sub(SSSSNumber b) {
      if (b instanceof SSSSDouble) {
        SSSSDouble bDouble = (SSSSDouble) b;
        return new SSSSDouble(value - bDouble.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    public SSSSNumber mul(SSSSNumber b) {
      if (b instanceof SSSSDouble) {
        SSSSDouble bDouble = (SSSSDouble) b;
        return new SSSSDouble(value * bDouble.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    public SSSSNumber div(SSSSNumber b) {
      if (b instanceof SSSSDouble) {
        SSSSDouble bDouble = (SSSSDouble) b;
        return new SSSSDouble(value / bDouble.value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    public SSSSNumber neg() {
      return new SSSSDouble(-value);
    }
    
    public SSSSNumber zero() {
      return new SSSSDouble(0);
    }
    
    public SSSSNumber one() {
      return new SSSSDouble(1);
    }
    
    public int intValue() {
      return (int) value;
    }
    
    public long longValue() {
      return (long) value;
    }
    
    public float floatValue() {
      return (float) value;
    }
    
    public double doubleValue() {
      return (double) value;
    }
    
    public boolean equals(Object o) {
      if (o instanceof SSSSDouble) {
        return (value == ((SSSSDouble) o).value);
      } else {
        return false;
      }
    }

    public String toString() {
      return Double.toString(value);
    }
    
    public SSSSDouble clone() {
      return new SSSSDouble(this.doubleValue());
    }
  }

  /**
   * Subclass of SSSSNumber for polynomials
   */
  private static final class SSSSPolynomial extends SSSSNumber {
    
    /**
     * Polynomial coefficients
     */
    SSSSNumber[] coefficients;

    public SSSSPolynomial(SSSSNumber[] c) {
      
      this.coefficients = new SSSSNumber[c.length];
      
      for (int i = 0; i < c.length; i++) {
        if (null == c[i]) {
          throw new RuntimeException("Null coefficient for degree " + i);
        }
        this.coefficients[i] = c[i].clone();
      }
    }

    /**
     * Compute the value of polynomial at x
     * @param x
     * @return
     */
    public SSSSNumber f(SSSSNumber x) {
      SSSSNumber result = coefficients[coefficients.length - 1];

      for (int i = coefficients.length - 1; i > 0; i--) {
        result = result.mul(x);
        result = result.add(coefficients[i - 1]);
      }

      return result;
    }

    public SSSSNumber add(SSSSNumber b) {
      SSSSNumber[] result;

      if (b instanceof SSSSPolynomial) {
        SSSSPolynomial bPoly = (SSSSPolynomial) b;
        
        int degMin = Math.min(coefficients.length, bPoly.coefficients.length);
        int degMax = Math.max(coefficients.length, bPoly.coefficients.length);
        boolean bBigger = (bPoly.coefficients.length > coefficients.length);
          
        result = new SSSSNumber[degMax];

        for (int i = 0; i < degMin; i++) {
          result[i] = coefficients[i].add(bPoly.coefficients[i]);
        }

        for (int i = degMin; i < degMax; i++) {
          if (bBigger) {
            result[i] = bPoly.coefficients[i];
          } else {
            result[i] = coefficients[i];
          }
        } 
      } else {
        result = copy();
        result[0].add(b);
      }

      return new SSSSPolynomial(result);
    }

    public SSSSNumber sub(SSSSNumber b) {
      SSSSNumber[] result;

      if (b instanceof SSSSPolynomial) {
        SSSSPolynomial bPoly = (SSSSPolynomial) b;
        
        int degMin = Math.min(coefficients.length, bPoly.coefficients.length);
        int degMax = Math.max(coefficients.length, bPoly.coefficients.length);
        boolean bBigger = (bPoly.coefficients.length > coefficients.length);
        
        result = new SSSSNumber[degMax];
        
        for (int i = 0; i < degMin; i++) {
          result[i] = coefficients[i].sub(bPoly.coefficients[i]);
        }

        for (int i = degMin; i < degMax; i++) {
          if (bBigger) {
            result[i] = bPoly.coefficients[i].neg();
          } else {
            result[i] = coefficients[i];
          }
        } 
      } else {
        result = copy();
        result[0].add(b);
      }

      return new SSSSPolynomial(result);
    }

    public SSSSNumber mul(SSSSNumber b) {
      SSSSNumber[] result;

      if (b instanceof SSSSPolynomial) {
        SSSSPolynomial bPoly = (SSSSPolynomial) b;
        result = new SSSSNumber[coefficients.length + bPoly.coefficients.length - 1];

        for (int i = 0; i < coefficients.length; i++) {
          for (int j = 0; j < bPoly.coefficients.length; j++) {
            SSSSNumber co = coefficients[i].mul(bPoly.coefficients[j]);

            if (result[i + j] == null) {
              result[i + j] = co;
            } else {
              result[i + j] = result[i + j].add(co);
            }
          }
        }
      } else {
        result = copy();

        for (int i = 0; i < result.length; i++) {
          result[i] = result[i].mul(b);
        }
      }

      return new SSSSPolynomial(result);
    }

    public SSSSNumber div(SSSSNumber b) {
      return null;
    }

    public SSSSNumber neg() {
      SSSSNumber[] result = copy();

      for (int i = 0; i < result.length; i++) {
        result[i] = result[i].neg();
      }

      return new SSSSPolynomial(result);
    }

    public SSSSNumber zero() {
      return coefficients[0].zero();
    }

    public SSSSNumber one() {
      return coefficients[0].one();
    }

    public int getDegree() {
      if (coefficients.length > 0) {
        return coefficients.length - 1;
      } else {
        return 0;
      }
    }

    public SSSSNumber getCoefficient(int index) {
      return coefficients[index];
    }
    
    public int intValue() {
      return coefficients[0].intValue();
    }
    
    public long longValue() {
      return coefficients[0].longValue();
    }
    
    public float floatValue() {
      return coefficients[0].floatValue();
    }
    
    public double doubleValue() {
      return coefficients[0].doubleValue();
    }
    
    private SSSSNumber[] copy() {
      SSSSNumber[] result = new SSSSNumber[coefficients.length];
      System.arraycopy(coefficients, 0, result, 0, coefficients.length);
      return result;
    }

    private int degree(SSSSNumber[] coeff) {
      if (null == coeff) {
        return 0;
      }

      for (int i = coeff.length - 1; i >= 0; i--) {
        if (!coeff[i].equals(coeff[i].zero())) {
          return i;
        }
      }

      return 0;
    }

    public String toString() {
      StringBuilder result = new StringBuilder();

      for (int i = getDegree(); i >= 0; i--) {
        result.append(getCoefficient(i));
        result.append("*x^");
        result.append(i);
        result.append(' ');
      }

      return result.toString();
    }
    
    public SSSSPolynomial clone() {
      return new SSSSPolynomial(this.coefficients);
    }
  }

  /**
   * A point has two coordinates (x,y) of type {@link SSSSNumber}.
   */
  private static final class SSSSXY extends SSSSNumber {
    SSSSNumber x;
    SSSSNumber y;

    /**
     * Create a new point.
     *
     * @param x The x coordinate of this point.
     * @param y The y coordinate of this point.
     */
    public SSSSXY(SSSSNumber x, SSSSNumber y) {
      this.x = x;
      this.y = y;
    }
    
    public SSSSNumber add(SSSSNumber b) {
      if (b instanceof SSSSXY) {
        SSSSXY bXY = (SSSSXY) b;
        
        return new SSSSXY(getX().add(bXY.getX()), getY().add(bXY.getY()));
      } else {
        throw new UnsupportedOperationException("Need to add an instance of SSSSXY.");
      }
    }

    public SSSSNumber sub(SSSSNumber b) {
      if (b instanceof SSSSXY) {
        SSSSXY bXY = (SSSSXY) b;

        return new SSSSXY(getX().sub(bXY.getX()), getY().sub(bXY.getY()));
      } else {
        throw new UnsupportedOperationException("Need to add an instance of SSSSXY.");
      }
    }

    /**
     * Multiplication of two XY is defined as a new XY whose coordinates
     * are the product of each member's matching coordinates
     */
    public SSSSNumber mul(SSSSNumber b) {
      if (b instanceof SSSSXY) {
        SSSSXY bXY = (SSSSXY) b;

        return new SSSSXY(getX().mul(bXY.getX()), getY().mul(bXY.getY()));
      } else {
        return new SSSSXY(getX().mul(b), getY().mul(b));
      }
    }

    /**
     * Division of two XY is defined as a new XY whose coordinates are
     * the results of the division of each dividend's coordinate by the matching coordinate of the
     * divisor
     */
    public SSSSNumber div(SSSSNumber b) {
      if (b instanceof SSSSXY) {
        SSSSXY bXY = (SSSSXY) b;
        
        return new SSSSXY(getX().div(bXY.getX()), getY().div(bXY.getY()));
      } else {
        return new SSSSXY(getX().div(b), getY().div(b));
      }
    }

    public SSSSNumber neg() {
      return new SSSSXY(getX().neg(), getY().neg());
    }
    
    public SSSSNumber zero() {
      return new SSSSXY(getX().zero(), getY().zero());
    }
    
    public SSSSNumber one() {
      return new SSSSXY(getX().one(), getY().one());
    }
    
    public SSSSNumber getX() {
      return this.x;
    }
    
    public SSSSNumber getY() {
      return this.y;
    }
    
    public int intValue() {
      throw new UnsupportedOperationException();
    }
    
    public long longValue() {
      throw new UnsupportedOperationException();
    }
    
    public float floatValue() {
      throw new UnsupportedOperationException();
    }
    
    public double doubleValue() {
      throw new UnsupportedOperationException();
    }
    
    public SSSSXY clone() {
      return new SSSSXY(this.x, this.y);
    }
  }


  /**
   * This exception is throw when two points with the same x coordinate are encountered in
   * an {@link SSSSPolynomialInterpolator}.
   */
  private static class SSSSDuplicateAbscissaException extends Exception {
    public SSSSDuplicateAbscissaException() {
      super("Abscissa collision detected during interpolation");
    }
  }

  /**
   * Interface of polynomial interpolator
   */
  private static interface SSSSPolynomialInterpolator {
    /**
     * Find a polynomial that interpolates the given points.  
     *
     * @param points Set of points to interpolate
     * @return The polynomial passing through the given points.
     * @throws SSSSDuplicateAbscissaException If any two points share the same x coordinate.
     */
    public SSSSPolynomial interpolate(SSSSXY[] points) throws SSSSDuplicateAbscissaException;
  }

  /**
   * Polynomial interpolator using Lagrange polynomials
   * 
   * @see http://en.wikipedia.org/wiki/Lagrange_polynomial
   */
  private static class SSSSLagrangePolynomialInterpolator implements SSSSPolynomialInterpolator {
    
    public SSSSPolynomial interpolate(SSSSXY[] points) throws SSSSDuplicateAbscissaException {   
      SSSSNumber result = null;

      //
      // Check x coordinates
      //
      
      checkPointSeparation(points);
      
      //
      // Build the interpolating polynomial as a linear combination
      // of Lagrange basis polynomials
      //
      
      for (int j = 0; j < points.length; j++) {
        if (result != null) {
          result = result.add(Lj(points, j)); 
        } else {
          result = Lj(points, j);
        }
      }

      return (SSSSPolynomial) result;
    }

    /**
     * Checks that a set of points does not contain points with identical x coordinates.
     * 
     * @param points Set of points to check.
     * @throws SSSSDuplicateAbscissaException if identical x coordinates exist
     */
    private void checkPointSeparation(SSSSXY[] points) throws SSSSDuplicateAbscissaException {
      for (int i = 0; i < points.length - 1; i++) {
        for (int j = i + 1; j < points.length; j++) {
          if (points[i].getX().equals(points[j].getX())) {
            throw new SSSSDuplicateAbscissaException();
          }              
        }
      }
    }

    /**
     * Return the j'th Lagrange basis polynomial
     * 
     * @param points Set of points to interpolate
     * @param j Index of polynomial to return
     * @return
     */
    private SSSSNumber Lj(SSSSXY[] points, int j) {
      SSSSNumber one = points[0].getX().one();

      SSSSNumber[] resultP = new SSSSNumber[1];

      resultP[0] = points[j].getY();

      SSSSNumber[] product = new SSSSNumber[2];
      SSSSNumber result = new SSSSPolynomial(resultP);

      for (int i = 0; i < points.length; i++) {
        if (i == j) {
          continue;
        }

        SSSSNumber numerator;
        SSSSNumber denominator;
          
        numerator = one;
        denominator = points[j].getX().sub(points[i].getX());
        product[1] = numerator.div(denominator);  

        numerator = points[i].getX();
        denominator = points[i].getX().sub(points[j].getX());
        product[0] = numerator.div(denominator);

        SSSSPolynomial poly = new SSSSPolynomial(product);
          
        result = result.mul(poly);
      }
      
      return result;
    }
  }
  
  /**
   * This class represents polynomials over GF(256)
   * 
   * GF(p^n) is a finite (or Galois) field, p being prime.
   * 
   * @see http://mathworld.wolfram.com/FiniteField.html
   *
   * The advantage of GF(256) is that it contains 256 elements
   * so each byte value can be considered a polynomial over GF(256)
   * and arithmetic rules can be implemented that represent polynomial
   * arithmetic in GF(256).
   * 
   * Each byte is mapped to a polynomial using the following rule:
   * 
   * Bit n of a byte is the polynomial coefficient of x^n.
   * 
   * So 0x0D = 0b00001101 = x^3 + x^2 + 1
   * 
   * The modulo polynomial used to generate this field is
   * 
   * x^8 + x^4 + x^3 + x^2 + 1
   * 
   * 0x011D = 0b0000000100011101
   */
  public static final class SSSSGF256Polynomial extends SSSSNumber {
    
    /**
     * Value representing the polynomial
     */
    private short value;

    /**
     * Generator used to generate the exp/log tables
     * 
     * For QR/Code generator is 0x02 and Prime polynomial 0x11d
     * For Rijndael generator is 0x03 and Prime polynomial 0x11b
     */
    private static final int GF256_GENERATOR = 0x02;
    
    /**
     * Prime polynomial used to generate the exp/log tables
     */
    private static final int GF256_PRIME_POLYNOMIAL = 0x11d;
    
    public static final short[] GF256_exptable;
    public static final short[] GF256_logtable;
        
    static {
      //
      // Generate GF256 exp/log tables
      // @see http://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders
      // @see http://www.samiam.org/galois.html
      //
      
      GF256_exptable = new short[256];
      GF256_logtable = new short[256];
      
      GF256_logtable[0] = (1 - 256) & 0xff;
      GF256_exptable[0] = 1;
      
      for (int i = 1; i < 256; i++) {
        int exp = GF256_exptable[i - 1] * GF256_GENERATOR;
        if (exp >= 256) {
          exp ^= GF256_PRIME_POLYNOMIAL;
        }
        exp &= 0xff;
        GF256_exptable[i] = (short) exp;

        // Generator^255 = Generator^0 so we use the power modulo 255
        // @see http://math.stackexchange.com/questions/76045/reed-solomon-polynomial-generator
        GF256_logtable[GF256_exptable[i]] = (short) (((short) i) % 255);
      }
    }

    /**
     * @param v The integer representing the polynomial in this
     *          field.  A bit i = 2<sup>n</sup> is set iff
     *          x<sup>n</sup> is a term in the polynomial.
     */
    public SSSSGF256Polynomial(int v) {
      value = (short) v;
    }

    /**
     * Implement addition on GF256, polynomial coefficients are
     * XORed
     * 
     * @param b The SSSSGF256Polynomial to add
     * @throws RuntimeException in case of type mismatch
     */
    public SSSSNumber add(SSSSNumber b) {
      if (b instanceof SSSSGF256Polynomial) {
        SSSSGF256Polynomial bPoly = (SSSSGF256Polynomial) b;
        return new SSSSGF256Polynomial(bPoly.value ^ value);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }

    /**
     * Polynomial subtraction is really an addition since in
     * GF(2^n), a + b = a - b
     *
     * @param b SSSSGF256Polynomial to subtract
     * @throws RuntimeException in case of type mismatch
     */
    public SSSSNumber sub(SSSSNumber b) {
      return add(b);
    }

    /**
     * Multiplication in GF256.
     *     
     * @param b The second term.  It must also be a GF256.
     * @throws RuntimeException If the second term is not of type
     *         GF256.
     */
    public SSSSNumber mul(SSSSNumber b) {
      if (b instanceof SSSSGF256Polynomial) {
        SSSSGF256Polynomial bPoly = (SSSSGF256Polynomial) b;
        
        //
        // Handle the special case of 0
        // 0 * x = x * 0 = 0
        //
        if ((bPoly.value == 0) || (value == 0)) {
          return zero();
        }
        
        //
        // In the general case, multiplication is done using logarithms
        // @see http://www.logic.at/wiki/index.php/GF(256)
        //
        // log(a * b) = log(a) + log(b)
        //
        
        // Modulo is 255 because there are only 255 values in the log table
        int newPower = (log() + bPoly.log()) % 255;
        
        return new SSSSGF256Polynomial(GF256_exptable[newPower]);
      } else {
        throw new RuntimeException("Type mismatch.");
      }
    }

    /**
     * Division in GF256.
     *     
     * @param b The second term.  It must also be a GF256.
     * @throws RuntimeException If the second term is not of type
     *         GF256 or if we divide by 0.
     */
    public SSSSNumber div(SSSSNumber b) {
      if (b instanceof SSSSGF256Polynomial) {
        SSSSGF256Polynomial bPoly = (SSSSGF256Polynomial) b;

        //
        // Cannot divide by 0
        //
        
        if (bPoly.value == 0) {
          throw new RuntimeException("Division by zero.");
        }
        
        //
        // 0 / x = 0
        //
        
        if (value == 0) {
          return zero();
        }
              
        //
        // Use the log rule:
        // @see http://www.logic.at/wiki/index.php/GF(256)
        //
        // log(a/b) = log(a) - log(b)
        //
        
        int newPower = (log() - bPoly.log()) % 255;
        
        if (newPower < 0) {
          newPower += 255;
        }

        return (SSSSNumber) new SSSSGF256Polynomial(GF256_exptable[newPower]);
      } else {
        throw new RuntimeException("Type mismatch");
      }
    }
      
    /**
     * a + a = 0, so a = -a.
     *
     * @return The arithmetic inverse of the current value.
     */
    public SSSSNumber neg() {
      return new SSSSGF256Polynomial(-value);
    }

    /**
     * @return The arithmetic identity.
     */
    public SSSSNumber zero() {
      return new SSSSGF256Polynomial(0);
    }

    /**
     * @return The multiplicative identity.
     */
    public SSSSNumber one() {
      return new SSSSGF256Polynomial(1);
    }

    public int intValue() {
      return (int) value;
    }
    
    public long longValue() {
      return (long) value;
    }
    
    public float floatValue() {
      return (float) value;
    }
    
    public double doubleValue() {
      return (double) value;
    }

    /**
     * @return The value n such that x<sup>n</n> is equivalent to
     *         the current polynomial in this field.
     */
    private int log() {
      if (0 == value) {
        throw new RuntimeException("Cannot take log of 0");
      }
          
      return GF256_logtable[value];
    }

    public String toString() {
      return Short.toString(value);
    }
    
    public int hashCode() { return value; }
    
    public boolean equals(Object o) {
      if (o instanceof SSSSGF256Polynomial) {
        SSSSGF256Polynomial oPoly = (SSSSGF256Polynomial) o;
        
        if (oPoly.value == value) {
          return true;
        }
      }
      
      return false;
    }
    
    @Override
    public SSSSGF256Polynomial clone() {
      return new SSSSGF256Polynomial(this.intValue());
    }
  } 

  /**
   * Implements a Shamir Secret Sharing Scheme.
   * 
   * An input stream of bytes (the secret) is split by an encoder
   * in a number (n) of keys (byte streams) so that k of those keys
   * can be combined by a decoder to recreate the secret.
   */
  public static final class SSSS  {
    
    /**
     * Polynomial interpolator
     */
    private SSSSPolynomialInterpolator interpolator;
    
    /**
     * Pseudo Random Number Generator
     */
    private SecureRandom prng;

    /**
     * Create an encoder/decoder using the default 
     * PRNG and the Lagrange polynomial interpolator.
     */
    public SSSS() {
      interpolator = new SSSSLagrangePolynomialInterpolator();
      prng = CryptoHelper.sr;
    }
      
    /**
     * Create an encoder using the Lagrange polynomial interpolator
     * and the specified SecureRandom implementation.
     *
     * @param rand The SecureRandom instance to use.
     */
    public SSSS(SecureRandom rand) {
      interpolator = new SSSSLagrangePolynomialInterpolator();
      prng = rand;
    }

    /**
     * Create an encoder using the specified SecureRandom implementation
     * and the specified SSSSPolynomialInterpolator.
     *
     * @param rand The SecureRandom instance to use.
     * @param pi The SSSSPolynomialInterpolator instance to use
     */
    public SSSS(SecureRandom rand, SSSSPolynomialInterpolator pi) {
      interpolator = pi;
      prng = rand;
    }

    /**
     * Given k keys, recreate the secret.
     * If the keys are the wrong ones, the produced data will be random.
     * To further detect that situation, the secret should contain a
     * control mechanism to validate the decoded data.
     * 
     * The decode method operates on streams so input and output can
     * be of any size.
     * 
     * @param result The OutputStream to which the reconstructed secret will be written
     * @param keys Key InputStreams
     * @throws IOException in case of I/O errors
     * @throws SSSSDuplicateAbscissaException If the keys cover identical points, probably because they're the wrong ones
     */
    public void decode(OutputStream result, InputStream[] keys) throws IOException, SSSSDuplicateAbscissaException {
      SSSSXY[] pGroup;

      do {
        pGroup = readPoints(keys);
        
        if (pGroup != null) {
          result.write(decodeByte(pGroup));
        }
      } while (pGroup != null);
    }

    private int decodeByte(SSSSXY[] points) throws IOException, SSSSDuplicateAbscissaException {
      SSSSPolynomial fit = interpolator.interpolate(points);
          
      //
      // Decoded byte is P(0) where P is the polynomial which interpolates all points.
      //
      
      SSSSGF256Polynomial result = (SSSSGF256Polynomial) fit.f(new SSSSGF256Polynomial(0));
          
      return result.intValue();
    }

    /**
     * Read one point from each key
     * 
     * @param keys Key InputStreams
     * @return An array of SSSSXY instances or null if EOF is reached on one key
     * @throws IOException
     */
    private SSSSXY[] readPoints(InputStream[] keys) throws IOException {
      SSSSXY[] result = new SSSSXY[keys.length];
      int xVal, yVal;

      //
      // Read one valid x/y pair per key
      //
      
      for (int i = 0; i < result.length; i++) {
        
        //
        // Read one x/y pair, skipping pairs whose x coordinate is 0
        //
        
        do {
          xVal = keys[i].read();
          if (xVal < 0) {
            return null;
          }
          yVal = keys[i].read();
          if (yVal < 0) {
            return null;
          }
        } while (xVal == 0);
      
        //
        // X and Y coordinates are GF256 polynomials
        //
        result[i] = new SSSSXY(new SSSSGF256Polynomial(xVal), new SSSSGF256Polynomial(yVal));
      }

      return result;
    }

      
    /**
     * Given a secret, write out the keys representing that secret.
     * 
     * @param input The InputStream containing the secret
     * @param keys OutputStreams for each of the keys.
     *
     * @throws IOException If there's an I/O error reading or writing
     */
    public void encode(InputStream input, OutputStream[] keys, int keysNeeded) throws IOException {
      
      //
      // If n < 2 or n > 255 or k < 2 we cannot split, ditto if k > n
      //
      
      if (keys.length < 2 || keys.length > 255 || keysNeeded < 2 || keysNeeded > keys.length)  {
        throw new RuntimeException("Need to have at least 2 keys and at most 255 and more keys than number of needed keys.");
      }

      int v;

      do {
        //
        // Read input byte
        //
        
        v = input.read();
              
        if (v >= 0) {
          encodeByte(v, keys, keysNeeded);
        }
      } while (v >= 0);
    }

    /**
     * Encode a byte
     * 
     * @param byteVal Byte value to encode
     * @param keys OutputStreams for the keys
     * @param keysNeeded Number of keys needed to reconstruct the secret
     * @throws IOException if an I/O error occurs
     */
    private void encodeByte(int byteVal, OutputStream[] keys, int keysNeeded) throws IOException {
      //
      // Array of boolean to keep track of x values already chosen
      //
      boolean[] picked = new boolean[256];
      
      //
      // Select a random polynomial whose value at 0 is the byte value to encode
      // The degree of the polynomial is the number of keys needed to reconstruct the secret minus one
      // (Because N points determine uniquely a polynomial of degree N-1, i.e. two points a line, three a parabola...)
      //      
      SSSSPolynomial rPoly = selectRandomPolynomial(keysNeeded - 1, new SSSSGF256Polynomial(byteVal));

      //
      // Pick a distinct x value per key.
      // If 0 is chosen as x value, generate a random byte as the associated y coordinate
      // and pick another x value.
      // 0 cannot be chosen as P(0) is the encoded value, but we cannot ignore 0 otherwise the
      // keys would fail a randomness test (since they would not contain enough 0s)
      //
      
      for (int i = 0; i < keys.length; i++) {
        int xPick;
        
        do {
          //
          // Pick a random x value
          //
          
          xPick = getRandomByte();
          
          //
          // If we picked 0, write it out with a random y value to
          // pass randomness tests
          //
          if (xPick == 0) {
            keys[i].write(xPick);
            keys[i].write(getRandomByte());
          }
          
          // Do so while we picked 0 or an already picked x value
        } while ((xPick == 0) || (picked[xPick] == true));
        
        // Marked the current x value as picked
        picked[xPick] = true;
        
        // Generate x/y 
        SSSSGF256Polynomial xVal = new SSSSGF256Polynomial(xPick);
        SSSSGF256Polynomial yVal = (SSSSGF256Polynomial) rPoly.f(xVal);

        // Write x/y pair
        keys[i].write(xVal.intValue());
        keys[i].write(yVal.intValue());
      } 
    }

    /**
     * Select a random polynomial with coefficients in GF256 whose degree and
     * value at the origin are fixed.
     * 
     * @param degree Degree of the polynomial to generate
     * @param c0 Value of P(0)
     * @return
     */
    private SSSSPolynomial selectRandomPolynomial(int degree, SSSSGF256Polynomial c0) {
      SSSSNumber[] coeff = new SSSSNumber[degree + 1];

      coeff[0] = c0;

      for (int i = 1; i < degree; i++) {
        coeff[i] = new SSSSGF256Polynomial(getRandomByte());
      }

      int cDegree;

      //
      // Make sure coefficient for 'degree' is non 0
      //
      
      do {
        cDegree = getRandomByte();
      } while (cDegree == 0);
      
      coeff[degree] = new SSSSGF256Polynomial(cDegree);

      return new SSSSPolynomial(coeff);
    }

    /**
     * Generate a single byte using the provided PRNG
     * 
     * @return A random byte
     */
    private int getRandomByte() {
      byte[] v = new byte[1];

      prng.nextBytes(v);

      return (int) (v[0] & 0xff);
    }
  }

  /**
   * Split 'data' in N parts, K of which are needed to recover 'data'.
   *
   * K should be > N/2 so there are no two independent sets of secrets
   * in the wild which could be used to recover the initial data.
   * 
   * @param data
   * @param n
   * @param k
   * @return
   */
  
  public static List<byte[]> SSSSSplit(byte[] data, int n, int k) {
    
    //
    // If n < 2 or k < 2 we cannot split, ditto if k > n
    //
    
    if (n < 2 || n > 255 || k < 2 || k > n)  {
      return null;
    }
        
    List<byte[]> secrets = new ArrayList<byte[]>();
    
    SSSS ss = new SSSS();

    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    
    ByteArrayOutputStream[] baos = new ByteArrayOutputStream[n];
    
    for (int i = 0; i < n; i++) {
      baos[i] = new ByteArrayOutputStream();
    }
    
    try {
      ss.encode (bais, baos, k);
    } catch (IOException ioe) {
      return null;
    }
    
    //
    // Retrieve secrets from ByteArrayOutputStream instances
    //
    
    for (int i = 0; i < n; i++) {
      secrets.add(baos[i].toByteArray());
    }
    
    return secrets;
  }
  
  /**
   * Recover data from a list of secrets which is a sublist of a list generated by 'split'
   * 
   * @param secrets
   * @return
   */
  
  public static byte[] SSSSRecover(Collection<byte[]> secrets) {
    SSSS ss = new SSSS();
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    ByteArrayInputStream[] bais = new ByteArrayInputStream[secrets.size()];
    
    int i = 0;
    
    for (byte[] secret: secrets) {
      bais[i] = new ByteArrayInputStream(secret);
      i++;
    }
   
    try {
      ss.decode(baos, bais);
    } catch (SSSSDuplicateAbscissaException dpe) {
      return null;
    } catch (IOException ioe) {
      return null;
    }
    
    return baos.toByteArray();
  }

  //
  // PGP Related code
  //
  
  public static List<PGPPublicKey> PGPPublicKeysFromKeyRing(String keyring) throws IOException {
    PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(new ByteArrayInputStream(keyring.getBytes("UTF-8"))));
    
    List<PGPPublicKey> pubkeys = new ArrayList<PGPPublicKey>();

    do {
      Object o = factory.nextObject();
    
      if (null == o) {
        break;
      }
      
      if (o instanceof PGPKeyRing) {
        PGPKeyRing ring = (PGPKeyRing) o;
      
        Iterator<PGPPublicKey> iter = ring.getPublicKeys();
      
        while(iter.hasNext()) {
          PGPPublicKey key = iter.next();        
          pubkeys.add(key);
        }
      }
    } while (true);
    
    return pubkeys;
  }
  
  public static byte[] encryptPGP(byte[] data, PGPPublicKey key, boolean armored, String name, int compressionAlgorithm, int encAlgorithm) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    OutputStream out = armored ? new ArmoredOutputStream(baos) : baos;
  
    BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(encAlgorithm);
    dataEncryptor.setWithIntegrityPacket(true);
    dataEncryptor.setSecureRandom(CryptoHelper.getSecureRandom());
    
    PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
    encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));

    try {
      OutputStream encout = encryptedDataGenerator.open(out, 1024);          
      
      PGPCompressedDataGenerator pgpcdg = new PGPCompressedDataGenerator(compressionAlgorithm);
      OutputStream compout = pgpcdg.open(encout);
      
      PGPLiteralDataGenerator pgpldg = new PGPLiteralDataGenerator(false);
      OutputStream ldout = pgpldg.open(compout, PGPLiteralData.BINARY, name, data.length, PGPLiteralData.NOW);
      
      ldout.write(data);
      ldout.close();
      compout.close();
      encout.close();
      out.close();
      baos.close();
      
      return baos.toByteArray();
    } catch (PGPException pgpe) {
      throw new IOException(pgpe);
    }
  }
  
}
