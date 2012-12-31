package com.geoxp.oss.servlet;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.openpgp.PGPPublicKey;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.MasterSecretGenerator;
import com.geoxp.oss.OSSException;
import com.google.gson.JsonObject;
import com.google.inject.Singleton;

@Singleton
public class GenMasterSecretServlet extends HttpServlet {
  
  /**
   * Name of parameter containing PGP pubrings
   */
  public static final String PARAM_PUBRING = "pubring";
  
  /**
   * Name of parameter containing PGP key ids
   */
  public static final String PARAM_KEYID = "keyid";
  
  /**
   * Name of parameter containing the number of shares needed to reconstruct the secret
   */
  public static final String PARAM_K = "k";  
  
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    //
    // Extract list of PGP Public Key Rings
    //
    
    String[] pubrings = request.getParameterValues(PARAM_PUBRING);
    
    if (null == pubrings) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing '" + PARAM_PUBRING + "' parameter.");
      return;
    }
    
    //
    // Extract list of PGP Public Key IDs
    //
    
    String[] keyids = request.getParameterValues(PARAM_KEYID);
    
    if (null == keyids) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing paramater '" + PARAM_KEYID + "'.");
      return;
    }

    if (null == request.getParameter(PARAM_K)) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameter '" + PARAM_K + "'.");
      return;
    }
    
    int k = Integer.valueOf(request.getParameter(PARAM_K));
    
    //
    // Extract public keys from key rings
    //
    
    List<PGPPublicKey> keys = new ArrayList<PGPPublicKey>();
    
    for (String pubring: pubrings) {
      List<PGPPublicKey> pubkeys = CryptoHelper.PGPPublicKeysFromKeyRing(pubring);
      
      for (PGPPublicKey key: pubkeys) {
        //
        // Generate hex version of key id
        //
        String id = "000000000000000" + Long.toHexString(key.getKeyID()).toLowerCase();
        id = id.substring(id.length() - 16);
        
        //
        // Add the key if it is in 'keyids'
        //
        
        for (String keyid: keyids) {
          if (id.endsWith(keyid.toLowerCase())) {
            keys.add(key);
            break;
          }
        }
      }      
    }
    
    //
    // If we have fewer keys than the number of ids specified, throw an error
    //
    
    if (keys.size() < keyids.length) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Some keys specified in '" + PARAM_KEYID + "' were not found in the provided key rings.");
      return;
    }

    //
    // Generate the master secret
    //
    
    try {
      
      Map<PGPPublicKey, byte[]> shares = MasterSecretGenerator.generate(keys, k);
      
      //
      // Produce JSON output
      //
      
      JsonObject json = new JsonObject();
      JsonObject jsonShares = new JsonObject();
      
      for (Entry<PGPPublicKey, byte[]> entry: shares.entrySet()) {
        String id = "000000000000000" + Long.toHexString(entry.getKey().getKeyID());
        id = id.substring(id.length() - 16);
        
        jsonShares.addProperty(id, new String(entry.getValue(), "UTF-8"));
      }

      json.add("shares", jsonShares);
      
      response.setContentType("application/json");
      response.getWriter().print(json.toString());
      
    } catch (OSSException osse) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, osse.getMessage());
    }
  }
}
