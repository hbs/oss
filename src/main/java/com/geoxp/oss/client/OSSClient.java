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

package com.geoxp.oss.client;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Base64;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.CryptoHelper.SSHAgentClient;
import com.geoxp.oss.CryptoHelper.SSHAgentClient.SSHKey;
import com.geoxp.oss.OSSException;
import com.geoxp.oss.servlet.GenMasterSecretServlet;
import com.geoxp.oss.servlet.GuiceServletModule;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OSSClient {
  
  public static Map<String,String> genMasterSecret(String ossURL, List<String> pubrings, List<String> pgpkeyids, int k) throws OSSException {
    
    try {
      URIBuilder builder = new URIBuilder(ossURL + GuiceServletModule.SERVLET_PATH_GEN_MASTER_SECRET);
      
      builder.setParameter(GenMasterSecretServlet.PARAM_K, Integer.toString(k));
      
      for (String keyid: pgpkeyids) {
        builder.addParameter(GenMasterSecretServlet.PARAM_KEYID, keyid);
      }

      for (String pubring: pubrings) {
        builder.addParameter(GenMasterSecretServlet.PARAM_PUBRING, pubring);
      }
      
      URI uri = builder.build();
      
      String qs = uri.getRawQuery();
      
      HttpClient httpclient = new DefaultHttpClient();
      
      HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());
      
      post.setHeader("Content-Type", "application/x-www-form-urlencoded");
      
      post.setEntity(new StringEntity(qs));
      
      HttpResponse response = httpclient.execute(post);
      HttpEntity resEntity = response.getEntity();
      String content = EntityUtils.toString(resEntity, "UTF-8");

      post.reset();
      
      if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
        throw new OSSException(response.getStatusLine().getReasonPhrase());
      }
      
      JsonParser parser = new JsonParser();
      JsonElement elt = parser.parse(content);

      JsonObject obj = elt.getAsJsonObject();

      Map<String,String> shares = new HashMap<String, String>();
      
      for (Entry<String, JsonElement> entry: obj.getAsJsonObject("shares").entrySet()) {
        shares.put(entry.getKey(), entry.getValue().getAsString());
      }
      
      return shares;
      
    } catch (Exception e) {
      throw new OSSException(e);
    }    
  }
  
  public static void genSecret(String ossURL, String secretName, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      
      agent = new SSHAgentClient();

      List<SSHKey> sshkeys = agent.requestIdentities();

      //
      // If no SSH Key fingerprint was provided, try all SSH keys available in the agent
      //

      List<String> fingerprints = new ArrayList<String>();

      if (null == sshKeyFingerprint) {
        for (SSHKey key: sshkeys) {
          fingerprints.add(key.fingerprint);
        }
      } else {
        fingerprints.add(sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", ""));
      }

      int idx = 0;

      for (String fingerprint: fingerprints) {
        idx++;
        
        //
        // Check if the signing key is available in the agent
        //
                
        byte[] keyblob = null;
        
        for (SSHKey key: sshkeys) {
          if (key.fingerprint.equals(fingerprint)) {
            keyblob = key.blob;
            break;
          }
        }
        
        //
        // Throw an exception if this condition is encountered as it can only happen if
        // there was a provided fingerprint which is not in the agent.
        //

        if (null == keyblob) {
          throw new OSSException("SSH Key " + sshKeyFingerprint + " was not found by your SSH agent.");
        }

        //
        // Build OSS Token
        //
        // <TS> <SECRET_NAME> <SSH Signing Key Blob> <SSH Signature Blob>
        //
        
        ByteArrayOutputStream token = new ByteArrayOutputStream();
        
        byte[] tsdata = new byte[8];
        long ts = System.currentTimeMillis();
        
        tsdata[0] = (byte) ((ts >> 56) & 0xff);
        tsdata[1] = (byte) ((ts >> 48) & 0xff);
        tsdata[2] = (byte) ((ts >> 40) & 0xff);
        tsdata[3] = (byte) ((ts >> 32) & 0xff);
        tsdata[4] = (byte) ((ts >> 24) & 0xff);
        tsdata[5] = (byte) ((ts >> 16) & 0xff);
        tsdata[6] = (byte) ((ts >> 8) & 0xff);
        tsdata[7] = (byte) (ts & 0xff);
        
        token.write(CryptoHelper.encodeNetworkString(tsdata));

        token.write(CryptoHelper.encodeNetworkString(secretName.getBytes("UTF-8")));
        
        token.write(CryptoHelper.encodeNetworkString(keyblob));
        
        //
        // Generate signature
        //
        
        byte[] sigblob = agent.sign(keyblob, token.toByteArray());
        
        token.write(CryptoHelper.encodeNetworkString(sigblob));
        
        String b64token = new String(Base64.encode(token.toByteArray()), "UTF-8");
        
        //
        // Send request
        //
        
        HttpClient httpclient = new DefaultHttpClient();
        
        URIBuilder builder = new URIBuilder(ossURL + GuiceServletModule.SERVLET_PATH_GEN_SECRET);
        
        builder.addParameter("token", b64token);
        
        URI uri = builder.build();
        
        String qs = uri.getRawQuery();
        
        HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());
        
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        post.setEntity(new StringEntity(qs));
        
        HttpResponse response = httpclient.execute(post);
        post.reset();
        
        if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
          // Only throw an exception if this is the last SSH key we could try
          if (idx == fingerprints.size()) {
            throw new OSSException("None of the provided keys (" + idx + ") could be used to generate secret. Latest error message was: " + response.getStatusLine().getReasonPhrase());
          } else {
            continue;
          }
        }
        
        return;
      }
    } catch (OSSException osse) {
      throw osse;
    } catch (Exception e) { 
      throw new OSSException(e);
    } finally {
      if (null != agent) {
        agent.close();
      }
    }
  }
  
  public static byte[] getSecret(String ossURL, String secretName, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      agent = new SSHAgentClient();

      List<SSHKey> sshkeys = agent.requestIdentities();

      //
      // If no SSH Key fingerprint was provided, try all SSH keys available in the agent
      //

      List<String> fingerprints = new ArrayList<String>();

      if (null == sshKeyFingerprint) {
        for (SSHKey key: sshkeys) {
          fingerprints.add(key.fingerprint);
        }
      } else {
        fingerprints.add(sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", ""));
      }

      int idx = 0;

      for (String fingerprint: fingerprints) {
        idx++;

        //
        // Check if the signing key is available in the agent
        //
      
        byte[] keyblob = null;
      
        for (SSHKey key: sshkeys) {
          if (key.fingerprint.equals(fingerprint)) {
            keyblob = key.blob;
            break;
          }
        }
      
        //
        // Throw an exception if this condition is encountered as it can only happen if
        // there was a provided fingerprint which is not in the agent.
        //

        if (null == keyblob) {
          throw new OSSException("SSH Key " + sshKeyFingerprint + " was not found by your SSH agent.");
        }

        //
        // Generate temporary RSA key pair
        //
      
        RSAKeyPairGenerator rsagen = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("65537"), CryptoHelper.getSecureRandom(), 2048, 64);
        rsagen.init(params);
        final AsymmetricCipherKeyPair keypair = rsagen.generateKeyPair();
      
        RSAPrivateKey rsapriv = new RSAPrivateKey() {
          public BigInteger getModulus() { return ((RSAKeyParameters) keypair.getPrivate()).getModulus(); }
          public String getFormat() { return "PKCS#8"; }
          public byte[] getEncoded() { return null; }
          public String getAlgorithm() { return "RSA"; }
          public BigInteger getPrivateExponent() { return ((RSAKeyParameters) keypair.getPrivate()).getExponent(); }
        };

        RSAPublicKey rsapub = new RSAPublicKey() {
          public BigInteger getModulus() { return ((RSAKeyParameters) keypair.getPublic()).getModulus(); }
          public String getFormat() { return "PKCS#8"; }
          public byte[] getEncoded() { return null; }
          public String getAlgorithm() { return "RSA"; }
          public BigInteger getPublicExponent() { return ((RSAKeyParameters) keypair.getPublic()).getExponent(); }      
        };

        //
        // Build OSS Token
        //
        // <TS> <<SECRET_NAME> <RSA_ENC_KEY>> <SSH Signing Key Blob> <SSH Signature Blob>
        //
      
        ByteArrayOutputStream token = new ByteArrayOutputStream();
      
        byte[] tsdata = new byte[8];
        long ts = System.currentTimeMillis();
      
        tsdata[0] = (byte) ((ts >> 56) & 0xff);
        tsdata[1] = (byte) ((ts >> 48) & 0xff);
        tsdata[2] = (byte) ((ts >> 40) & 0xff);
        tsdata[3] = (byte) ((ts >> 32) & 0xff);
        tsdata[4] = (byte) ((ts >> 24) & 0xff);
        tsdata[5] = (byte) ((ts >> 16) & 0xff);
        tsdata[6] = (byte) ((ts >> 8) & 0xff);
        tsdata[7] = (byte) (ts & 0xff);
      
        token.write(CryptoHelper.encodeNetworkString(tsdata));

        ByteArrayOutputStream subtoken = new ByteArrayOutputStream();
      
        subtoken.write(CryptoHelper.encodeNetworkString(secretName.getBytes("UTF-8")));
        subtoken.write(CryptoHelper.encodeNetworkString(CryptoHelper.sshKeyBlobFromPublicKey(rsapub)));
      
        token.write(CryptoHelper.encodeNetworkString(subtoken.toByteArray()));
      
        token.write(CryptoHelper.encodeNetworkString(keyblob));
      
        //
        // Generate signature
        //
      
        byte[] sigblob = agent.sign(keyblob, token.toByteArray());
      
        token.write(CryptoHelper.encodeNetworkString(sigblob));
      
        String b64token = new String(Base64.encode(token.toByteArray()), "UTF-8");
      
        //
        // Send request
        //
      
        HttpClient httpclient = new DefaultHttpClient();
      
        URIBuilder builder = new URIBuilder(ossURL + GuiceServletModule.SERVLET_PATH_GET_SECRET);
      
        builder.addParameter("token", b64token);
      
        URI uri = builder.build();
      
        String qs = uri.getRawQuery();
      
        HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());
      
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
      
        post.setEntity(new StringEntity(qs));
      
        HttpResponse response = httpclient.execute(post);
        HttpEntity resEntity = response.getEntity();
        String content = EntityUtils.toString(resEntity, "UTF-8");
        post.reset();
      
        if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
          // Only throw an exception if this is the last SSH key we could try
          if (idx == fingerprints.size()) {
            throw new OSSException("None of the provided keys (" + idx + ") could be used to retrieve secret. Latest error message was: " + response.getStatusLine().getReasonPhrase());
          } else {
            continue;
          }
        }
      
        //
        // Extract encrypted secret and sealed key
        //
      
        byte[] secretandsealedkey = Base64.decode(content);
      
        byte[] encryptedsecret = CryptoHelper.decodeNetworkString(secretandsealedkey, 0);
        byte[] sealedkey = CryptoHelper.decodeNetworkString(secretandsealedkey, 4 + encryptedsecret.length);
      
        //
        // Unseal key
        //
      
        byte[] wrappingkey = CryptoHelper.decryptRSA(rsapriv, sealedkey);
      
        //
        // Unwrap secret
        //
            
        return CryptoHelper.unwrapAES(wrappingkey, encryptedsecret);      
      }
    } catch (OSSException osse) {
      throw osse;
    } catch (Exception e) {
      throw new OSSException(e);
    } finally {
      if (null != agent) {
        agent.close();
      }
    }

    return null;
  }
  
  public static boolean init(String ossURL, byte[] secret, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      agent = new SSHAgentClient();
      
      List<SSHKey> sshkeys = agent.requestIdentities();
      
      //
      // If no SSH Key fingerprint was provided, try all SSH keys available in the agent
      //

      List<String> fingerprints = new ArrayList<String>();

      if (null == sshKeyFingerprint) {
        for (SSHKey key: sshkeys) {
          fingerprints.add(key.fingerprint);
        }
      } else {
        fingerprints.add(sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", ""));
      }

      int idx = 0;

      for (String fingerprint: fingerprints) {
        idx++;
        
        //
        // Ask the SSH agent for the SSH key blob
        //
        
        byte[] keyblob = null;
        
        for (SSHKey key: sshkeys) {
          if (key.fingerprint.equals(fingerprint)) {
            keyblob = key.blob;
            break;
          }
        }
        
        //
        // Throw an exception if this condition is encountered as it can only happen if
        // there was a provided fingerprint which is not in the agent.
        //

        if (null == keyblob) {
          throw new OSSException("SSH Key " + sshKeyFingerprint + " was not found by your SSH agent.");
        }

        //
        // Retrieve OSS RSA key
        //

        HttpClient httpclient = new DefaultHttpClient();
        
        String getrsauri = ossURL + GuiceServletModule.SERVLET_PATH_GET_OSS_RSA;
        
        HttpGet get = new HttpGet(getrsauri);
        
        HttpResponse response = httpclient.execute(get);

        HttpEntity resEntity = response.getEntity();
        String content = EntityUtils.toString(resEntity, "UTF-8");
        
        get.reset();
        
        JsonParser parser = new JsonParser();
        JsonElement elt = parser.parse(content);
        final JsonObject rsa = elt.getAsJsonObject();
        
        RSAPublicKey pubkey = new RSAPublicKey() {
          public BigInteger getModulus() { return new BigInteger(rsa.get("modulus").getAsString()); }
          public String getFormat() { return "PKCS#8"; }
          public byte[] getEncoded() { return null; }
          public String getAlgorithm() { return "RSA"; }
          public BigInteger getPublicExponent() { return new BigInteger(rsa.get("exponent").getAsString()); }
        };
        
        //
        // Build the initialization token
        //
        // <TS> <SECRET> <SSH Signing Key Blob> <SSH Signature Blob>
        //
        
        ByteArrayOutputStream token = new ByteArrayOutputStream();
        
        byte[] tsdata = new byte[8];
        long ts = System.currentTimeMillis();
        
        tsdata[0] = (byte) ((ts >> 56) & 0xff);
        tsdata[1] = (byte) ((ts >> 48) & 0xff);
        tsdata[2] = (byte) ((ts >> 40) & 0xff);
        tsdata[3] = (byte) ((ts >> 32) & 0xff);
        tsdata[4] = (byte) ((ts >> 24) & 0xff);
        tsdata[5] = (byte) ((ts >> 16) & 0xff);
        tsdata[6] = (byte) ((ts >> 8) & 0xff);
        tsdata[7] = (byte) (ts & 0xff);
        
        token.write(CryptoHelper.encodeNetworkString(tsdata));
        
        token.write(CryptoHelper.encodeNetworkString(secret));
        
        token.write(CryptoHelper.encodeNetworkString(keyblob));
        
        byte[] sigblob = agent.sign(keyblob, token.toByteArray());
        
        token.write(CryptoHelper.encodeNetworkString(sigblob));
        
        //
        // Encrypt the token with a random AES256 key
        //
        
        byte[] aeskey = new byte[32];
        CryptoHelper.getSecureRandom().nextBytes(aeskey);
             
        byte[] wrappedtoken = CryptoHelper.wrapAES(aeskey, token.toByteArray());
        
        //
        // Encrypt the random key with OSS' RSA key
        //
             
        byte[] sealedaeskey = CryptoHelper.encryptRSA(pubkey, aeskey);
        
        //
        // Create the token
        //
        
        token.reset();
        
        token.write(CryptoHelper.encodeNetworkString(wrappedtoken));
        token.write(CryptoHelper.encodeNetworkString(sealedaeskey));
        
        //
        // Base64 encode the encryptedtoken
        //
        
        String b64token = new String(Base64.encode(token.toByteArray()), "UTF-8");
        
        //
        // Send request to OSS
        //
           
        URIBuilder builder = new URIBuilder(ossURL + GuiceServletModule.SERVLET_PATH_INIT);
        
        builder.addParameter("token", b64token);
        
        URI uri = builder.build();
        
        String qs = uri.getRawQuery();
        
        HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());
        
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        post.setEntity(new StringEntity(qs));
        
        response = httpclient.execute(post);
        resEntity = response.getEntity();
        content = EntityUtils.toString(resEntity, "UTF-8");

        post.reset();

        if (HttpServletResponse.SC_ACCEPTED == response.getStatusLine().getStatusCode()) {
          return false;
        } else if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
          // Only throw an exception if this is the last SSH key we could try
          if (idx == fingerprints.size()) {
            throw new OSSException("None of the provided keys (" + idx + ") could be used to initialize this Open Secret Server. Latest error message was: " + response.getStatusLine().getReasonPhrase());
          } else {
            continue;
          }
        }
        
        return true;
      }
      
    } catch (OSSException osse) {
      throw osse;
    } catch (Exception e) {
      throw new OSSException(e);
    } finally {
      if (null != agent) {
        agent.close();
      }
    }
    
    return false;
  }

  public static void putSecret(String ossURL, String secretname, byte[] secret, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      agent = new SSHAgentClient();
      
      List<SSHKey> sshkeys = agent.requestIdentities();
      
      //
      // If no SSH Key fingerprint was provided, try all SSH keys available in the agent
      //

      List<String> fingerprints = new ArrayList<String>();

      if (null == sshKeyFingerprint) {
        for (SSHKey key: sshkeys) {
          fingerprints.add(key.fingerprint);
        }
      } else {
        fingerprints.add(sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", ""));
      }

      int idx = 0;

      for (String fingerprint: fingerprints) {
        idx++;
        
        //
        // Ask the SSH agent for the SSH key blob
        //
        
        byte[] keyblob = null;
        
        for (SSHKey key: sshkeys) {
          if (key.fingerprint.equals(fingerprint)) {
            keyblob = key.blob;
            break;
          }
        }
        
        //
        // Throw an exception if this condition is encountered as it can only happen if
        // there was a provided fingerprint which is not in the agent.
        //

        if (null == keyblob) {
          throw new OSSException("SSH Key " + sshKeyFingerprint + " was not found by your SSH agent.");
        }

        //
        // Retrieve OSS RSA key
        //

        HttpClient httpclient = new DefaultHttpClient();
        
        String getrsauri = ossURL + GuiceServletModule.SERVLET_PATH_GET_OSS_RSA;
        
        HttpGet get = new HttpGet(getrsauri);
        
        HttpResponse response = httpclient.execute(get);

        HttpEntity resEntity = response.getEntity();
        String content = EntityUtils.toString(resEntity, "UTF-8");
        
        get.reset();
        
        JsonParser parser = new JsonParser();
        JsonElement elt = parser.parse(content);
        final JsonObject rsa = elt.getAsJsonObject();
        
        RSAPublicKey pubkey = new RSAPublicKey() {
          public BigInteger getModulus() { return new BigInteger(rsa.get("modulus").getAsString()); }
          public String getFormat() { return "PKCS#8"; }
          public byte[] getEncoded() { return null; }
          public String getAlgorithm() { return "RSA"; }
          public BigInteger getPublicExponent() { return new BigInteger(rsa.get("exponent").getAsString()); }
        };

        //
        // Build the token
        //
        // <TS> <<WRAPPED_SECRET><ENCRYPTED_WRAPPING_KEY>> <SSH Signing Key Blob> <SSH Signature Blob>
        //
        
        ByteArrayOutputStream token = new ByteArrayOutputStream();
        
        byte[] tsdata = new byte[8];
        long ts = System.currentTimeMillis();
        
        tsdata[0] = (byte) ((ts >> 56) & 0xff);
        tsdata[1] = (byte) ((ts >> 48) & 0xff);
        tsdata[2] = (byte) ((ts >> 40) & 0xff);
        tsdata[3] = (byte) ((ts >> 32) & 0xff);
        tsdata[4] = (byte) ((ts >> 24) & 0xff);
        tsdata[5] = (byte) ((ts >> 16) & 0xff);
        tsdata[6] = (byte) ((ts >> 8) & 0xff);
        tsdata[7] = (byte) (ts & 0xff);
        
        token.write(CryptoHelper.encodeNetworkString(tsdata));
        
        ByteArrayOutputStream subtoken = new ByteArrayOutputStream();
        
        subtoken.write(CryptoHelper.encodeNetworkString(secretname.getBytes("UTF-8")));
        subtoken.write(CryptoHelper.encodeNetworkString(secret));
        
        token.write(CryptoHelper.encodeNetworkString(subtoken.toByteArray()));
        
        token.write(CryptoHelper.encodeNetworkString(keyblob));
        
        byte[] sigblob = agent.sign(keyblob, token.toByteArray());
        
        token.write(CryptoHelper.encodeNetworkString(sigblob));
        
        //
        // Encrypt the token with a random AES256 key
        //
        
        byte[] aeskey = new byte[32];
        CryptoHelper.getSecureRandom().nextBytes(aeskey);
             
        byte[] wrappedtoken = CryptoHelper.wrapAES(aeskey, token.toByteArray());
        
        //
        // Encrypt the random key with OSS' RSA key
        //
             
        byte[] sealedaeskey = CryptoHelper.encryptRSA(pubkey, aeskey);
        
        //
        // Create the token
        //
        
        token.reset();
        
        token.write(CryptoHelper.encodeNetworkString(wrappedtoken));
        token.write(CryptoHelper.encodeNetworkString(sealedaeskey));
        
        //
        // Base64 encode the encryptedtoken
        //
        
        String b64token = new String(Base64.encode(token.toByteArray()), "UTF-8");
        
        //
        // Send request to OSS
        //
           
        URIBuilder builder = new URIBuilder(ossURL + GuiceServletModule.SERVLET_PATH_PUT_SECRET);
        
        builder.addParameter("token", b64token);
        
        URI uri = builder.build();
        
        String qs = uri.getRawQuery();
        
        HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());
        
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        post.setEntity(new StringEntity(qs));
        
        response = httpclient.execute(post);
        resEntity = response.getEntity();
        content = EntityUtils.toString(resEntity, "UTF-8");

        post.reset();

        if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
          // Only throw an exception if this is the last SSH key we could try
          if (idx == fingerprints.size()) {
            throw new OSSException("None of the provided keys (" + idx + ") could be used to store the secret. Latest error message was: " + response.getStatusLine().getReasonPhrase());
          } else {
            continue;
          }
        }
        
        return;
      }      
    } catch (OSSException osse) {
      throw osse;
    } catch (Exception e) {
      throw new OSSException(e);
    } finally {
      if (null != agent) {
        agent.close();
      }
    }
  }
}
