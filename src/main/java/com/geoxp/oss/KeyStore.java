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

import java.io.File;
import java.io.IOException;

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
   * Return the File of the ACL associated with the secret.
   * 
   * @param name
   * @return
   * @throws OSSException
   */
  public abstract File getACLFile(String name) throws IOException, OSSException;
  
  /**
   * Sanitize secret name
   * 
   * @param name Name to sanitize
   * @return The sanitized name
   * @throws OSSException if secret name is invalid
   */
  public static String sanitizeSecretName(String name) throws OSSException {
    if (null == name || "".equals(name)) {
      return name;
    }
    
    String sanitized = name.toLowerCase().replaceAll("[^a-z0-9.-]", "");

    if (!name.equals(sanitized)) {
      throw new OSSException("Secret name can only contain characters 'a' to 'z', '0' to '9', '-' and '.'");
    }

    return sanitized;
  }
}
