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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.OSS;
import com.geoxp.oss.OSSException;
import com.google.inject.Singleton;

@Singleton
public class InitServlet extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    
    //
    // If OSS is already initialized, bail out
    //
    
    if (OSS.isInitialized()) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Open Secret Server already initialized.");
      return;
    }
    
    //
    // Extract token
    //
    
    String b64token = req.getParameter("token");
    
    //
    // Decode it from base64
    //
    
    byte[] token = Base64.decode(b64token);
    
    //
    // Extract wrapped init token and sealed AES key
    //
    
    byte[] wrappedtoken = CryptoHelper.decodeNetworkString(token, 0);
    byte[] sealedaeskey = CryptoHelper.decodeNetworkString(token, wrappedtoken.length + 4);
    
    //
    // Unseal AES key
    //
    
    byte[] aeskey = CryptoHelper.decryptRSA(OSS.getSessionRSAPrivateKey(), sealedaeskey);
    
    //
    // Unwrap init token
    //
    
    byte[] inittoken = CryptoHelper.unwrapAES(aeskey, wrappedtoken);
    
    //
    // Check OSS Token
    //
    
    OSS.OSSToken osstoken = null;
    
    try {
      osstoken = OSS.checkToken(inittoken);
    } catch (OSSException osse) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
      return;
    }
    
    //
    // Check signing key fingerprint
    //
    
    if (!OSS.checkInitSSHKey(osstoken.getKeyblob())) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "SSH signing key is not authorized to initialize this Open Secret Server.");
      return;
    }
    
    //
    // Add secret to initialization
    //
    
    try {
      OSS.init(osstoken.getSecret());
    } catch (OSSException osse) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
      return;      
    }
    
    if (!OSS.isInitialized()) {
      resp.sendError(HttpServletResponse.SC_ACCEPTED, "Open Secret Server not yet initialized, needs some more secrets.");
      return;
    }
    
    resp.setStatus(HttpServletResponse.SC_OK);
  }
}
