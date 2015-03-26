package com.geoxp.oss.servlet;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.PublicKey;
import java.util.Arrays;

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
public class GetACLServlet extends HttpServlet {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(GetACLServlet.class);
  
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    
    if (!OSS.isInitialized()) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Open Secret Server not yet initialized.");
      return;
    }

    if (!OSS.hasSecureACLs()) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Secure ACLs are not enabled.");
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
    // Check OSS Token
    //
    
    OSS.OSSToken osstoken = null;
    
    try {
      osstoken = OSS.checkToken(token);
    } catch (OSSException osse) {
      LOGGER.error("doPost", osse);
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
      return;
    }
    
    //
    // Check that ssh key can change ACLs
    //
    
    if (!OSS.checkACLSSHKey(osstoken.getKeyblob())) {
      resp.sendError(HttpServletResponse.SC_FORBIDDEN, "SSH Key is not allowed to access ACLs.");
      return;
    }
    
    //
    // Extract secretname and RSA pubkey
    //
    
    byte[] secretname = CryptoHelper.decodeNetworkString(osstoken.getSecret(), 0);
    byte[] keyblob = CryptoHelper.decodeNetworkString(osstoken.getSecret(), 4 + secretname.length);
    
    //
    // Read existing ACLs
    //
    
    File aclfile = null;
    
    try {
      aclfile = OSS.getKeyStore().getACLFile(new String(secretname, "UTF-8"));
    } catch (OSSException osse) {
      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, osse.getMessage());
      return;
    }

    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    if (aclfile.exists()) {
      InputStream in = new FileInputStream(aclfile);
      byte[] buffer = new byte[1024];
      
      while(true) {
        int len = in.read(buffer);
        
        if (len < 0) {
          break;
        }
        
        baos.write(buffer, 0, len);
      }
      
      in.close();
      
      byte[] k = OSS.getMasterSecret();
      String acls = new String(CryptoHelper.unwrapBlob(k, baos.toByteArray()), "UTF-8");
      Arrays.fill(k, (byte) 0);
      
      BufferedReader br = new BufferedReader(new StringReader(acls));
      
      //
      // Add all fingerprints
      //
      
      baos.reset();
      
      while(true) {
        String line = br.readLine();
        if (null == line) { 
          break;
        }
        baos.write(CryptoHelper.encodeNetworkString(Hex.decode(line)));
      }
      
      br.close();      
    }

    //
    // Wrap list of fingerprints with random AES key and wrap key with provided RSA key
    //
    
    PublicKey pubkey = CryptoHelper.sshKeyBlobToPublicKey(keyblob);
    
    byte[] aeskey = new byte[32];
    CryptoHelper.getSecureRandom().nextBytes(aeskey);
    
    byte[] wrapped = CryptoHelper.wrapAES(aeskey, baos.toByteArray());
    
    baos.reset();
    baos.write(CryptoHelper.encodeNetworkString(wrapped));
    baos.write(CryptoHelper.encodeNetworkString(CryptoHelper.encryptRSA(pubkey, aeskey)));
    
    resp.setStatus(HttpServletResponse.SC_OK);
    resp.getWriter().println(new String(Base64.encode(baos.toByteArray()), "UTF-8"));
  }
}
