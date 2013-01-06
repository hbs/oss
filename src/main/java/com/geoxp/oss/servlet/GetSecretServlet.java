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

package com.geoxp.oss.servlet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.OSS;
import com.geoxp.oss.OSS.OSSToken;
import com.geoxp.oss.OSSException;
import com.google.inject.Singleton;

@Singleton
public class GetSecretServlet extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

    if (!OSS.isInitialized()) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Open Secret Server not yet initialized.");
      return;
    }

    //
    // Extract token
    //
    
    String token = req.getParameter("token");
    
    if (null == token) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'token'.");
    }
    
    //
    // Decode token
    //
    
    byte[] tokendata = Base64.decode(token);
    
    //
    // Extract OSS Token
    //
    
    OSSToken osstoken = null;
    
    try {
      osstoken = OSS.checkToken(tokendata);
    } catch (OSSException osse) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
      return;
    }

    //
    // Extract secretname and RSA pub key from secret
    //
    
    byte[] secretname = CryptoHelper.decodeNetworkString(osstoken.getSecret(), 0);
    byte[] rsapubblob = CryptoHelper.decodeNetworkString(osstoken.getSecret(), secretname.length + 4);
    
    //
    // Retrieve secret
    //
    
    byte[] secret = null;
    
    try {          
      secret = OSS.getKeyStore().getSecret(new String(secretname, "UTF-8"), new String(Hex.encode(CryptoHelper.sshKeyBlobFingerprint(osstoken.getKeyblob()))));
    } catch (OSSException e) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
      return;
    }
    
    //
    // Unwrap secret
    //
    
    secret = CryptoHelper.unwrapAES(OSS.getMasterSecret(), secret);
   
    if (null == secret) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Secret integrity failed.");
      return;
    }
           
    //
    // Wrap secret (excluding nonce) with a temporary AES key
    //
    
    byte[] wrappingkey = new byte[32];
    CryptoHelper.getSecureRandom().nextBytes(wrappingkey);
    
    secret = CryptoHelper.wrapAES(wrappingkey, secret, OSS.NONCE_BYTES, secret.length - OSS.NONCE_BYTES);
        
    //
    // Seal wrapping key with provided RSA pub key
    //
    
    PublicKey rsapub = CryptoHelper.sshKeyBlobToPublicKey(rsapubblob);
        
    byte[] sealedwrappingkey = CryptoHelper.encryptRSA(rsapub, wrappingkey);
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(CryptoHelper.encodeNetworkString(secret));
    baos.write(CryptoHelper.encodeNetworkString(sealedwrappingkey));
    
    resp.setStatus(HttpServletResponse.SC_OK);
    
    resp.getWriter().println(new String(Base64.encode(baos.toByteArray()), "UTF-8"));
  }
}
