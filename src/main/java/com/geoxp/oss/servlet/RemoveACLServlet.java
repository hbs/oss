package com.geoxp.oss.servlet;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.OSS;
import com.geoxp.oss.OSSException;
import com.google.inject.Singleton;

@Singleton
public class RemoveACLServlet extends HttpServlet {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(RemoveACLServlet.class);
  
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
    // Check that ssh key can change ACLs
    //
    
    if (!OSS.checkACLSSHKey(osstoken.getKeyblob())) {
      resp.sendError(HttpServletResponse.SC_FORBIDDEN, "SSH Key is not allowed to access ACLs.");
      return;
    }
    
    //
    // Extract secretname and SSH key fingerprints
    //
    
    byte[] secretname = CryptoHelper.decodeNetworkString(osstoken.getSecret(), 0);
    
    Set<String> removefingerprints = new HashSet<String>();
    
    int offset = secretname.length + 4;
    
    while (offset < osstoken.getSecret().length) {
      byte[] fpr = CryptoHelper.decodeNetworkString(osstoken.getSecret(), offset);
      offset += fpr.length + 4;
      String fingerprint = new String(fpr, "UTF-8").toLowerCase().replaceAll("[^a-f0-9]", "");
      
      if (32 != fingerprint.length()) {
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid fingerprint length.");
        return;
      }
      
      removefingerprints.add(fingerprint);
    }

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

    Set<String> fingerprints = new HashSet<String>();
    
    if (aclfile.exists()) {
      InputStream in = new FileInputStream(aclfile);
      byte[] buffer = new byte[1024];
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      
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
      
      while(true) {
        String line = br.readLine();
        if (null == line) {
          break;
        }
        fingerprints.add(line);
      }
      
      br.close();      
    }
    
    //
    // Remove fingerprints
    //
    
    int oldsize = fingerprints.size();
    
    for(String fingerprint: removefingerprints) {
      fingerprints.remove(fingerprint);
    }
    
    //
    // No fingerprints were removed, return immediately
    //
    
    if (oldsize == fingerprints.size()) {
      resp.setStatus(HttpServletResponse.SC_OK);
      return;
    }
    
    //
    // If the ACL is now empty, remove the ACL file
    //
    
    if (fingerprints.isEmpty() && aclfile.exists()) {
      aclfile.delete();
    } else {
      
      //
      // Build new ACL list
      //
      
      StringBuilder sb = new StringBuilder();
      for (String fingerprint: fingerprints) {
        sb.append(fingerprint.toLowerCase().replaceAll("[^0-9a-f]",""));
        sb.append("\n");
      }
      
      //
      // Write ACL file
      //
      
      synchronized(OSS.getKeyStore()) {
        OutputStream os = new FileOutputStream(aclfile);
        os.write(CryptoHelper.wrapBlob(OSS.getMasterSecret(), sb.toString().getBytes("UTF-8")));
        os.close();
      }           
    }
    resp.setStatus(HttpServletResponse.SC_OK);
  }
}
