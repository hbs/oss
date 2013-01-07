package com.geoxp.oss.servlet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.OSS;
import com.geoxp.oss.OSSException;
import com.google.inject.Singleton;

@Singleton
public class PutSecretServlet extends HttpServlet {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(PutSecretServlet.class);
  
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    
    if (!OSS.isInitialized()) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Open Secret Server not yet initialized.");
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
      LOGGER.error("doPost", osse);
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
      return;
    }
    
    //
    // Extract secretname and secret content
    //
    
    byte[] secretname = CryptoHelper.decodeNetworkString(osstoken.getSecret(), 0);
    byte[] secret = CryptoHelper.decodeNetworkString(osstoken.getSecret(), secretname.length + 4);
    
    //
    // Check that key can store secrets
    //
    
    if (!OSS.checkPutSecretSSHKey(osstoken.getKeyblob())) {
      LOGGER.error("[" + new String(Hex.encode(CryptoHelper.sshKeyBlobFingerprint(osstoken.getKeyblob()))) + "] (unauthorized) attempted to store " + secret.length + " bytes as secret '" + secretname + "'");
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "SSH Key cannot store a secret.");
      return;  
    }

    //
    // Check secret length
    //
    
    if (secret.length > OSS.getMaxSecretSize()) {
      LOGGER.error("[" + new String(Hex.encode(CryptoHelper.sshKeyBlobFingerprint(osstoken.getKeyblob()))) + "] failed to store " + secret.length + "bytes (>" + OSS.getMaxSecretSize() +") as secret '" + secretname + "'");
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Secret cannot exceed " + OSS.getMaxSecretSize() + " bytes.");
      return;
    }
    
    //
    // Add nonce to secret prior to wrapping
    //
    
    byte[] nonce = new byte[OSS.NONCE_BYTES];
    CryptoHelper.getSecureRandom().nextBytes(nonce);
    
    ByteArrayOutputStream nonced = new ByteArrayOutputStream();
    nonced.write(nonce);
    nonced.write(secret);
    
    //
    // Attempt to store secret
    //
        
    try {          
      OSS.getKeyStore().putSecret(new String(secretname, "UTF-8"), CryptoHelper.wrapAES(OSS.getMasterSecret(), nonced.toByteArray()));
      LOGGER.info("[" + new String(Hex.encode(CryptoHelper.sshKeyBlobFingerprint(osstoken.getKeyblob()))) + "] stored " + secret.length + " bytes as secret '" + secretname + "'");
    } catch (OSSException e) {
      LOGGER.error("doPost", e);
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
      return;
    }
    
    resp.setStatus(HttpServletResponse.SC_OK);
  }
}
