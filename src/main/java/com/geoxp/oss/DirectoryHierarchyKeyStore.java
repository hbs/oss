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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;


public class DirectoryHierarchyKeyStore extends KeyStore {
  
  private final File directory;
  
  public DirectoryHierarchyKeyStore(String directory) {
    try {
      this.directory = new File(directory).getCanonicalFile();
    } catch (IOException ioe) {
      throw new RuntimeException("Unable to determine canonical path.");
    }
    
    if (!this.directory.exists() || !this.directory.isDirectory()) {
      throw new RuntimeException("Invalid directory '" + this.directory.getAbsolutePath() + "'");
    }
  }
  
  @Override
  public byte[] getSecret(String name, String fingerprint) throws OSSException {    
    try {
      //
      // Sanitize name
      //
      
      name = sanitizeSecretName(name);
      
      File root = getSecretFile(name);
      
      File secretFile = new File(root.getAbsolutePath() + ".secret");
      File aclFile = findACLFile(name);
      
      //
      // Check if secret exists
      //
      
      if (!secretFile.exists() || !secretFile.isFile() || null == aclFile || !aclFile.exists() || !aclFile.isFile()) {
        throw new OSSException("Missing secret or ACL file.");
      }

      //
      // Check ACLs
      //

      // Sanitize fingerprint
      
      if (null == fingerprint) {
        fingerprint = "";
      }
      
      fingerprint = fingerprint.toLowerCase().replaceAll("[^0-9a-f]","");
      
      boolean authorized = false;
      
      Reader reader;
      
      if (!OSS.hasSecureACLs()) {
        reader = new FileReader(aclFile);
      } else {
        //
        // Read ACL blob and unwrap it
        //
        InputStream in = new FileInputStream(aclFile);
        byte[] buf = new byte[1024];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while(true) {
          int len = in.read(buf);
          if (len < 0) {
            break;
          }
          baos.write(buf, 0, len);
        }
        in.close();
        reader = new StringReader(new String(CryptoHelper.unwrapBlob(OSS.getMasterSecret(), baos.toByteArray()), "UTF-8"));
      }
      
      try {
        BufferedReader br = new BufferedReader(reader);
        
        while(true) {
          String line = br.readLine();
          
          if (null == line) {
            break;
          }
          
          String acl = line.toLowerCase().replaceAll("[^0-9a-f#*]", "");
          
          if ("*".equals(acl) || fingerprint.equals(acl)) {
            authorized = true;
            break;
          }
        }
        
        br.close();      
      } catch (IOException ioe) {
        throw new OSSException(ioe);
      }
      
      if (!authorized) {
        throw new OSSException("Access denied.");
      }
      
      //
      // Read secret
      //
      
      ByteArrayOutputStream baos = new ByteArrayOutputStream((int) secretFile.length());
      
      byte[] buf = new byte[1024];
      
      try {
        InputStream is = new FileInputStream(secretFile);

        do {
          int len = is.read(buf);
          
          if (-1 == len) {
            break;
          }
          
          baos.write(buf, 0, len);
        } while(true);
        
        is.close();
      } catch (IOException ioe) {
        throw new OSSException(ioe);
      }
      
      return baos.toByteArray();
    } catch (IOException ioe) {
      throw new OSSException(ioe);
    }
  }
  
  @Override
  public void putSecret(String name, byte[] secret) throws OSSException {
    //
    // Sanitize name
    //
    
    name = sanitizeSecretName(name);
    
    File root = getSecretFile(name);
    
    File secretFile = new File(root.getAbsolutePath() + ".secret");
    
    if (secretFile.exists()) {
      throw new OSSException("Secret '" + name + "' already exists.");
    }
        
    //
    // Create hierarchy
    //
    
    if (secretFile.getParentFile().exists() && !secretFile.getParentFile().isDirectory()) {
      throw new OSSException("Secret path already exists and is not a directory.");
    }
    
    if (!secretFile.getParentFile().exists() && !secretFile.getParentFile().mkdirs()) {
      throw new OSSException("Unable to create path to secret file.");
    }
    
    try {
      
      OutputStream os = new FileOutputStream(secretFile);      
      os.write(secret);      
      os.close();
      
    } catch (IOException ioe) {
      throw new OSSException(ioe);
    }
  }  
  
  /**
   * Retrieve secret file from secret name
   * 
   * @param name
   * @return
   */
  private File getSecretFile(String name) throws OSSException {
    //
    // Sanitize name
    //
    
    name = sanitizeSecretName(name);
    
    //
    // Replace '.' with '/'
    //
    
    String[] tokens = name.split("\\.");
    
    File f;
    
    f = this.directory.getAbsoluteFile();
      
    for (int i = 0; i < tokens.length; i++) {
      f = new File(f, tokens[i]);
    }

    return f;
  }
  
  @Override
  public File getACLFile(String name) throws IOException, OSSException {
    File path = getSecretFile(name);
    
    return new File(path.getCanonicalPath() + ".acl");
  }
  
  /**
   * Determine the ACL file to use for a given secret
   * 
   * @param name Name of secret
   * @return File of ACLs or null if none is suitable
   */
  private File findACLFile(String name) throws IOException, OSSException {
    File path = getSecretFile(name);
    
    while (!path.equals(this.directory)) {
      File acl = new File(path.getCanonicalPath() + ".acl");
      
      if (acl.exists() && acl.isFile()) {
        return acl;
      }
      
      path = path.getParentFile();
    }
    
    return null;
  }
}
