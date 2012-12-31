package com.geoxp.oss.servlet;

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
    // Seal secret with provided RSA pub key
    //
    
    PublicKey rsapub = CryptoHelper.sshKeyBlobToPublicKey(rsapubblob);
    
    byte[] sealedsecret = CryptoHelper.encryptRSA(rsapub, secret);
    
    resp.setStatus(HttpServletResponse.SC_OK);
    
    resp.getWriter().println(new String(Base64.encode(sealedsecret), "UTF-8"));

  }
}
