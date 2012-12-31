package com.geoxp.oss.client;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class OSSClient {
  
  public static Map<String,String> genMasterSecret(String ossGenMasterSecretURL, List<String> pubrings, List<String> pgpkeyids, int k) throws OSSException {
    
    try {
      URIBuilder builder = new URIBuilder(ossGenMasterSecretURL);
      
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
  
  public static void genSecret(String ossGenSecretURL, String secretName, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      
      //
      // Check if the signing key is available in the agent
      //
      
      String fingerprint = sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", "");
      
      agent = new SSHAgentClient();
      
      List<SSHKey> sshkeys = agent.requestIdentities();
      
      byte[] keyblob = null;
      
      for (SSHKey key: sshkeys) {
        if (key.fingerprint.equals(fingerprint)) {
          keyblob = key.blob;
          break;
        }
      }
      
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
      
      URIBuilder builder = new URIBuilder(ossGenSecretURL);
      
      builder.addParameter("token", b64token);
      
      URI uri = builder.build();
      
      String qs = uri.getRawQuery();
      
      HttpPost post = new HttpPost(uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() + uri.getPath());
      
      post.setHeader("Content-Type", "application/x-www-form-urlencoded");
      
      post.setEntity(new StringEntity(qs));
      
      HttpResponse response = httpclient.execute(post);
      post.reset();
      
      if (HttpServletResponse.SC_OK != response.getStatusLine().getStatusCode()) {
        throw new OSSException(response.getStatusLine().getReasonPhrase());
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
  
  public static byte[] getSecret(String ossGetSecretURL, String secretName, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      //
      // Check if the signing key is available in the agent
      //
      
      String fingerprint = sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", "");
      
      agent = new SSHAgentClient();
      
      List<SSHKey> sshkeys = agent.requestIdentities();
      
      byte[] keyblob = null;
      
      for (SSHKey key: sshkeys) {
        if (key.fingerprint.equals(fingerprint)) {
          keyblob = key.blob;
          break;
        }
      }
      
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
      
      URIBuilder builder = new URIBuilder(ossGetSecretURL);
      
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
        throw new OSSException(response.getStatusLine().getReasonPhrase());
      }
      
      //
      // Extract sealed secret
      //
      
      byte[] sealedsecret = Base64.decode(content);
      
      //
      // Unseal secret
      //
      
      byte[] secret = CryptoHelper.decryptRSA(rsapriv, sealedsecret);
      
      return secret;      
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
  
  public static void init(String ossInitURL, String sshKeyFingerprint) throws OSSException {
    
    SSHAgentClient agent = null;
    
    try {
      //
      // Ask the SSH agent for the SSH key blob
      //
      
      String fingerprint = sshKeyFingerprint.toLowerCase().replaceAll("[^0-9a-f]", "");
      
      agent = new SSHAgentClient();
      
      List<SSHKey> sshkeys = agent.requestIdentities();
      
      byte[] keyblob = null;
      
      for (SSHKey key: sshkeys) {
        if (key.fingerprint.equals(fingerprint)) {
          keyblob = key.blob;
          break;
        }
      }
      
      if (null == keyblob) {
        throw new OSSException("SSH Key " + sshKeyFingerprint + " was not found by your SSH agent.");
      }

      //
      // Retrieve OSS RSA key
      //

      HttpClient httpclient = new DefaultHttpClient();
      
      String getrsauri = ossInitURL.replace("/Init", "/GetOSSRSA");
      
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
      // Read secret from stdin
      //
      
      ByteArrayOutputStream secret = new ByteArrayOutputStream();
      
      byte[] buf = new byte[1024];
      
      do {
        int len = System.in.read(buf);
        
        if (len < 0) {
          break;
        }
        
        secret.write(buf, 0, len);
      } while (true);
      
      secret.close();
      
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
      
      token.write(CryptoHelper.encodeNetworkString(secret.toByteArray()));
      
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
         
      URIBuilder builder = new URIBuilder(ossInitURL);
      
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
        throw new OSSException(response.getStatusLine().getReasonPhrase());
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
