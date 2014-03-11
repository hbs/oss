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
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.ProxySelector;
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
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.ProxySelectorRoutePlanner;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.CryptoHelper.SSHAgentClient;
import com.geoxp.oss.CryptoHelper.SSHAgentClient.SSHKey;
import com.geoxp.oss.MasterSecretGenerator;
import com.geoxp.oss.OSS;
import com.geoxp.oss.OSSException;
import com.geoxp.oss.servlet.GuiceServletModule;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OSSClient {

  /**
   * Name of property containing the OSS instance's RSA public key modulus and public exponent.
   */
  public static final String OSS_RSA = "oss.rsa";

  /**
   * Get an HttpClient able to use a the Java configured proxyHost/Port if needed
   *
   * @returns HttpClient
   */
  private static HttpClient newHttpClient() {
    DefaultHttpClient httpclient = new DefaultHttpClient();
    ProxySelectorRoutePlanner routePlanner = new ProxySelectorRoutePlanner(
        httpclient.getConnectionManager().getSchemeRegistry(),
        ProxySelector.getDefault());
    httpclient.setRoutePlanner(routePlanner);
    return httpclient;
  }

  public static Map<String,String> genMasterSecret(byte[] secret, List<String> pubrings, List<String> pgpkeyids, int k) throws OSSException {

    try {

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

          for (String keyid: pgpkeyids) {
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

      if (keys.size() < pgpkeyids.size()) {
        throw new OSSException("Some keys not present in the provided key rings.");
      }

      //
      // Generate the master secret
      //

      Map<PGPPublicKey, byte[]> shares = MasterSecretGenerator.generate(secret, keys, k);

      //
      // Produce JSON output
      //

      Map<String,String> strshares = new HashMap<String, String>();

      for (Entry<PGPPublicKey, byte[]> entry: shares.entrySet()) {
        String id = "000000000000000" + Long.toHexString(entry.getKey().getKeyID());
        id = id.substring(id.length() - 16);

        strshares.put(id, new String(entry.getValue(), "UTF-8"));
      }

      return strshares;
    } catch (Exception e) {
      throw new OSSException(e);
    }
  }

  public static void genSecret(String ossURL, String secretName, String sshKeyFingerprint) throws OSSException {

    SSHAgentClient agent = null;

    HttpClient httpclient = null;

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

        byte[] tsdata = nowBytes();

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

        httpclient = newHttpClient();

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
      if (null != httpclient) {
        httpclient.getConnectionManager().shutdown();
      }
      if (null != agent) {
        agent.close();
      }
    }
  }

  public static byte[] getSecret(String ossURL, String secretName, String sshKeyFingerprint) throws OSSException {

    HttpClient httpclient = null;

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
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("65537"), CryptoHelper.getSecureRandom(), OSS.DEFAULT_RSA_STRENGTH, 64);
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

        byte[] tsdata = nowBytes();

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

        httpclient = newHttpClient();

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
      if (null != httpclient) {
        httpclient.getConnectionManager().shutdown();
      }
      if (null != agent) {
        agent.close();
      }
    }

    return null;
  }

  public static boolean init(String ossURL, byte[] secret, String sshKeyFingerprint) throws OSSException {

    SSHAgentClient agent = null;

    HttpClient httpclient = newHttpClient();

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

        RSAPublicKey pubkey = getOSSRSA(ossURL);

        //
        // Build the initialization token
        //
        // <TS> <SECRET> <SSH Signing Key Blob> <SSH Signature Blob>
        //

        ByteArrayOutputStream token = new ByteArrayOutputStream();

        byte[] tsdata = nowBytes();

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

        httpclient = newHttpClient();

        HttpResponse response = httpclient.execute(post);
        HttpEntity resEntity = response.getEntity();
        String content = EntityUtils.toString(resEntity, "UTF-8");

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
      if (null != httpclient) {
        httpclient.getConnectionManager().shutdown();
      }
      if (null != agent) {
        agent.close();
      }
    }

    return false;
  }

  public static void putSecret(String ossURL, String secretname, byte[] secret, String sshKeyFingerprint) throws OSSException {

    SSHAgentClient agent = null;

    HttpClient httpclient = null;

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

        RSAPublicKey pubkey = getOSSRSA(ossURL);

        //
        // Build the token
        //
        // <TS> <<WRAPPED_SECRET><ENCRYPTED_WRAPPING_KEY>> <SSH Signing Key Blob> <SSH Signature Blob>
        //

        ByteArrayOutputStream token = new ByteArrayOutputStream();

        byte[] tsdata = nowBytes();

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

        httpclient = newHttpClient();

        HttpResponse response = httpclient.execute(post);
        HttpEntity resEntity = response.getEntity();
        String content = EntityUtils.toString(resEntity, "UTF-8");

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
      if (null != httpclient) {
        httpclient.getConnectionManager().shutdown();
      }
      if (null != agent) {
        agent.close();
      }
    }
  }

  public static void addACL(String ossURL, String sshKeyFingerprint, String secretname, List<String> keyfpr) throws OSSException {
    changeACL(false, ossURL, sshKeyFingerprint, secretname, keyfpr);
  }

  public static void removeACL(String ossURL, String sshKeyFingerprint, String secretname, List<String> keyfpr) throws OSSException {
    changeACL(true, ossURL, sshKeyFingerprint, secretname, keyfpr);
  }

  private static void changeACL(boolean remove, String ossURL, String sshKeyFingerprint, String secretname, List<String> keyfpr) throws OSSException {

    SSHAgentClient agent = null;

    HttpClient httpclient = null;

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

        RSAPublicKey pubkey = getOSSRSA(ossURL);

        //
        // Build the token
        //
        // <TS> <<SECRET_NAME><FINGERPRINT1>....<FINGERPRINTN>> <SSH Signing Key Blob> <SSH Signature Blob>
        //

        ByteArrayOutputStream token = new ByteArrayOutputStream();

        byte[] tsdata = nowBytes();

        token.write(CryptoHelper.encodeNetworkString(tsdata));

        ByteArrayOutputStream subtoken = new ByteArrayOutputStream();

        subtoken.write(CryptoHelper.encodeNetworkString(secretname.getBytes("UTF-8")));

        for (String fpr: keyfpr) {
          subtoken.write(CryptoHelper.encodeNetworkString(fpr.toLowerCase().replaceAll("[^a-f0-9]", "").getBytes("UTF-8")));
        }

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

        URIBuilder builder = new URIBuilder(ossURL + (remove ? GuiceServletModule.SERVLET_PATH_REMOVE_ACL : GuiceServletModule.SERVLET_PATH_ADD_ACL));

        builder.addParameter("token", b64token);

        URI uri = builder.build();

        String qs = uri.getRawQuery();

        HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());

        post.setHeader("Content-Type", "application/x-www-form-urlencoded");

        post.setEntity(new StringEntity(qs));

        httpclient = newHttpClient();

        HttpResponse response = httpclient.execute(post);
        HttpEntity resEntity = response.getEntity();
        String content = EntityUtils.toString(resEntity, "UTF-8");

        post.reset();

        if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
          // Only throw an exception if this is the last SSH key we could try
          if (idx == fingerprints.size()) {
            throw new OSSException("None of the provided keys (" + idx + ") could be used to modify ACL. Latest error message was: " + response.getStatusLine().getReasonPhrase());
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
      if (null != httpclient) {
        httpclient.getConnectionManager().shutdown();
      }
      if (null != agent) {
        agent.close();
      }
    }
  }

  public static List<String> getACL(String ossURL, String sshKeyFingerprint, String secretName) throws OSSException {

    SSHAgentClient agent = null;

    HttpClient httpclient = null;

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
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("65537"), CryptoHelper.getSecureRandom(), OSS.DEFAULT_RSA_STRENGTH, 64);
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

        byte[] tsdata = nowBytes();

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

        httpclient = newHttpClient();

        URIBuilder builder = new URIBuilder(ossURL + GuiceServletModule.SERVLET_PATH_GET_ACL);

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
            throw new OSSException("None of the provided keys (" + idx + ") could be used to retrieve ACLs. Latest error message was: " + response.getStatusLine().getReasonPhrase());
          } else {
            continue;
          }
        }

        //
        // Extract encrypted list of fingerprints and sealed key
        //

        byte[] fprandsealedkey = Base64.decode(content);

        byte[] encryptedfpr = CryptoHelper.decodeNetworkString(fprandsealedkey, 0);
        byte[] sealedkey = CryptoHelper.decodeNetworkString(fprandsealedkey, 4 + encryptedfpr.length);

        //
        // Unseal key
        //

        byte[] wrappingkey = CryptoHelper.decryptRSA(rsapriv, sealedkey);

        //
        // Unwrap fingerprints
        //

        byte[] fpr = CryptoHelper.unwrapAES(wrappingkey, encryptedfpr);

        int offset = 0;

        List<String> res = new ArrayList<String>();

        while (offset < fpr.length) {
          byte[] f = CryptoHelper.decodeNetworkString(fpr, offset);

          if (null == f) {
            break;
          }

          offset += 4 + f.length;

          if (0 < f.length) {
            res.add(new String(Hex.encode(f), "UTF-8").replaceAll("([0-9a-f]{2})","$1:"));
          }
        }

        return res;
      }
    } catch (OSSException osse) {
      throw osse;
    } catch (Exception e) {
      throw new OSSException(e);
    } finally {
      if (null != httpclient) {
        httpclient.getConnectionManager().shutdown();
      }
      if (null != agent) {
        agent.close();
      }
    }

    return null;
  }

  public static RSAPublicKey getOSSRSA(String ossURL) {

    if (null != System.getProperty(OSS_RSA)) {
      final String[] tokens = System.getProperty(OSS_RSA).split(":");

      RSAPublicKey pubkey = new RSAPublicKey() {
        public BigInteger getModulus() { return new BigInteger(tokens[0]); }
        public String getFormat() { return "PKCS#8"; }
        public byte[] getEncoded() { return null; }
        public String getAlgorithm() { return "RSA"; }
        public BigInteger getPublicExponent() { return new BigInteger(tokens[1]); }
      };

      return pubkey;
    } else {
      System.err.println("Unsecure OSS Instance RSA public key retrieval, you're not protected from Man-In-The-Middle type attacks.");
    }

    HttpClient httpclient = newHttpClient();

    try {
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

      return pubkey;
    } catch (ClientProtocolException cpe) {
      return null;
    } catch (IOException ioe) {
      return null;
    } finally {
      httpclient.getConnectionManager().shutdown();
    }
  }

  private static byte[] nowBytes() {
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

    return tsdata;
  }
}
