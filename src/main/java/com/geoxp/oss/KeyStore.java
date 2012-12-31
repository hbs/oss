package com.geoxp.oss;

public abstract class KeyStore {
  /**
   * Retrieve a secret
   * @param name Name of secret to retrieve
   * @param fingerprint SSH fingerprint of requesting key
   * @return The requested secret
   * @throws OSSException if an error occurred
   */
  public abstract byte[] getSecret(String name, String fingerprint) throws OSSException;
  
  /**
   * Store a secret in the keystore
   * 
   * @param name Name under which to store the secret
   * @param secret Secret to store.
   * @throws OSSException if an error occurred
   */
  public abstract void putSecret(String name, byte[] secret) throws OSSException;
  
  /**
   * Sanitize secret name
   * 
   * @param name Name to sanitize
   * @return The sanitized name
   */
  public static String sanitizeSecretName(String name) {
    if (null == name) {
      return name;
    }
    
    return name.toLowerCase().replaceAll("[^a-z0-9.-]", "");
  }
}
