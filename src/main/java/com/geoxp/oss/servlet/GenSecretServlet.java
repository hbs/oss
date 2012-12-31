package com.geoxp.oss.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.OSS;
import com.geoxp.oss.OSS.OSSToken;
import com.geoxp.oss.OSSException;
import com.google.inject.Singleton;

@Singleton
public class GenSecretServlet extends HttpServlet {
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
    // Check that requesting key can indeed generate secrets
    //
    
    if (!OSS.checkGenSecretSSHKey(osstoken.getKeyblob())) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "SSH Key cannot generate a new secret.");
      return;
    }
    
    //
    // Generate secret
    //
    
    byte[] secret = new byte[32];
    
    CryptoHelper.getSecureRandom().nextBytes(secret);
    
    //
    // Wrap with master key
    //
    
    byte[] wrappedsecret = CryptoHelper.wrapAES(OSS.getMasterSecret(), secret);
    
    try {
      OSS.getKeyStore().putSecret(new String(osstoken.getSecret(), "UTF-8"), wrappedsecret);
    } catch (OSSException osse) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
    }
    
    resp.setStatus(HttpServletResponse.SC_OK);
  }
}
