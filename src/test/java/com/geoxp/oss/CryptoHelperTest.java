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

package com.geoxp.oss;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.geoxp.oss.CryptoHelper.SSSSGF256Polynomial;


public class CryptoHelperTest {

  private static final String PLAINTEXT = "Too many secrets, Marty!";
  
  //
  // AES Wrapping tests
  //
  
  @Test
  public void testWrapAES_Ok() {
    try {
      byte[] data = PLAINTEXT.getBytes("UTF-8");
      byte[] key = "0123456789ABCDEF".getBytes();
      byte[] encrypted = CryptoHelper.wrapAES(key, data);
      
      Assert.assertEquals("b552b1f8a038ab01a90652321088e3520d641021409378624355c6fa8a6037ca9876dcafa74f6a0e", new String(Hex.encode(encrypted)));
    } catch (UnsupportedEncodingException uee) {
      Assert.assertTrue(false);
    }
  }
  
  @Test
  public void testUnwrapAES_Ok() {
    try {
      byte[] encrypted = Hex.decode("b552b1f8a038ab01a90652321088e3520d641021409378624355c6fa8a6037ca9876dcafa74f6a0e");
      byte[] key = "0123456789ABCDEF".getBytes();
      String data = new String(CryptoHelper.unwrapAES(key, encrypted), "UTF-8");
  
      Assert.assertEquals(PLAINTEXT, data);
    } catch (UnsupportedEncodingException uee) {
      Assert.assertTrue(false);
    }
  }
  
  @Test
  public void testUnwrapAES_WrongKey() {    
    byte[] encrypted = Hex.decode("b552b1f8a038ab01a90652321088e3520d641021409378624355c6fa8a6037ca9876dcafa74f6a0e");
    byte[] key = "0123456789ABCDEG".getBytes();
    byte[] data = CryptoHelper.unwrapAES(key, encrypted);
      
    Assert.assertEquals(null, data);
  }

  //
  // Padding tests
  //
  
  @Test
  public void testPadPKCS7() {
    byte[] data = new byte[8];
    byte[] padded = CryptoHelper.padPKCS7(8, data);
    
    Assert.assertEquals("00000000000000000808080808080808", new String(Hex.encode(padded)));
    
    data = new byte[0];
    padded = CryptoHelper.padPKCS7(8, data);
    
    Assert.assertEquals("0808080808080808", new String(Hex.encode(padded)));    

    data = new byte[3];
    padded = CryptoHelper.padPKCS7(8, data);
    
    Assert.assertEquals("0000000505050505", new String(Hex.encode(padded)));    
  }
  
  @Test
  public void testUnpadPKCS7() {
    try {
      byte[] padded = Hex.decode("00000000000000000808080808080808");
      byte[] data = CryptoHelper.unpadPKCS7(padded);
      
      Assert.assertEquals("0000000000000000", new String(Hex.encode(data)));      

      padded = Hex.decode("0808080808080808");
      data = CryptoHelper.unpadPKCS7(padded);
      
      Assert.assertEquals("", new String(Hex.encode(data)));      
      padded = Hex.decode("0000000505050505");
      data = CryptoHelper.unpadPKCS7(padded);
      
      Assert.assertEquals("000000", new String(Hex.encode(data)));      
    } catch (InvalidCipherTextException ice) {
      Assert.assertTrue(false);
    }
  }
  
  //
  // RSA Tests
  //
  
  private static RSAPublicKey pubkey = null;
  private static RSAPrivateKey privkey = null;
  
  private static String TEST_CIPHERTEXT = "416a5e39db06eff6b27880a1e5d060730ae9a45b28f245fe4e82d74976b72606d2062308a35db92d3d76cbf746bbed1dd6e51d3c60bbf897efce0ea11b4fd888ef61f59d1b8135479f72ba342935bab40f6484bcd8af087f815508fddb2502c4f2b24e393d682c2a439ee2a23ef148be0e3dae9d8bd60f6aeed2af41da07f3fe017702464b4f9073d5ff0e4883428d0bcb900d5fc0771d3c7d314830da7bcd0043f7cb7cbdaec59626f3e42edad4631a2a872917f8e52234dfe6052c53149952e73d12cedb4c8e844d31e0644d2fc01d67a567eb2b6fd099382804b6560acf2ff861f2a5a34ba34a4eed8b821aedf5f9447d249fcdcfb4ab412c66f057b407ba";
  private static String TEST_SHA256WITHRSA_SIG = "5572ce4db50487e52a4bd2707e557ceb9566a55937026a0fe2f8f6cdba2ce58e069b2efbcb69c8a293e651c8ca764c4c8d2d7de5a1f66290bd2720b6d1717cfda912eacae716d3e0f5251c9c266080709b21e9331ee79cc57fec90768169a9ea913e5f445579cc7c120c67bdb72a7f08ed05556b276daf0b174966c35738d8a35dd6268e2e94e676dade1c2567b4b8c0f39933dddaba6988569592954312eff378e6e51ccdf57fab2ce8961c7385831df58b18db5623d032eac7805611f0419ef2683b7d1716c639ee414e6f5809a68ce280c2edfe505a9c037b30b4646d5afd45a48a4d36a15a51370bf671c6a78baa2a4dd541f94f565b46af83a057af4717";
  private static String TEST_SHA1WITHRSA_SIG = "3ed203960c6b7c217aa1a48e5600245adf464771958e0bc4c30ef066b0bcd6e4de74af65b724cdab71c0c56d2a6dcf3c40ef675931dce64d12dd5462c4df2c54321cf4004526c97a28435ef6a51c3b28b0deefdcb33bfde7351b8eaf65a47f911cc40c4762a47cae4f4e94c7473aa714e134a4275f28a645e3bfe47dc541c63422dd64de19ba085f49d88f24b096ed67746e593b96fda7a7ea8b6a3f0e1516577771fd7f69e7d3ec168994f898867d793ab2f131563b4064ffa8d00eab8d19e61ec6b22906d1aa6e84efbac5fbd17b5e6a1024ee2296c1159f20107e4dc8418218b30ba2d0870448735d55e8435837da6381a44932495a90a7c60618359ab3e3";

  @BeforeClass
  public static void initRSA() {
    
    pubkey = new RSAPublicKey() {
      
      public BigInteger getModulus() { return new BigInteger("16486878486408275413767645980834450799068512761530201902904366269045701264780287813548482765230599547361495663114883133953031934796710541013969698908689227122243199249153028203405570632782038660366993871583035487813355780732353330307966740208839055253611521697790624599289584287035124227303722015732664143435627662572063369377319845149329865786129950696697707258169860504161097904037909901392070097285851111591152223867471834516850780920777180757773482764583645271112169550056347194865136966708230939966062717171772017703633226195925227390808476557633216288033679639392565309589416160575374495537295296004844165991833"); } 
      public String getFormat() { return "PKCS#8"; }
      public byte[] getEncoded() { return null; }
      public String getAlgorithm() { return "RSA"; }
      public BigInteger getPublicExponent() { return new BigInteger("65537"); }
    };
    
    privkey = new RSAPrivateKey() {
      
      public BigInteger getModulus() { return new BigInteger("16486878486408275413767645980834450799068512761530201902904366269045701264780287813548482765230599547361495663114883133953031934796710541013969698908689227122243199249153028203405570632782038660366993871583035487813355780732353330307966740208839055253611521697790624599289584287035124227303722015732664143435627662572063369377319845149329865786129950696697707258169860504161097904037909901392070097285851111591152223867471834516850780920777180757773482764583645271112169550056347194865136966708230939966062717171772017703633226195925227390808476557633216288033679639392565309589416160575374495537295296004844165991833"); } 
      public String getFormat() { return "PKCS#8"; }
      public byte[] getEncoded() { return null; }
      public String getAlgorithm() { return "RSA"; }
      public BigInteger getPrivateExponent() { return new BigInteger("16462225022080216287006438887038247491344498628282876578484807426035394434685097795608574754320844771347313955453786981441818465617314510786474253122445554933128960978765048943385524766751969542331136792384794227490092450605680296352030692776999541278073216173790693549489770757881677438859396447617831284347271984130596544116183151131396911078941742892944344866258139017288536308538106615887195873638366636746767960329159670221204748613353113007335636833020656797045918057345527985852226488193916871657682561742644875120607102033893450853383621001138933634164562229114010435736620936636769693547229391425790450273613"); }
    };

    /*
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    // For explanation of 'certainty', refer to http://bouncy-castle.1462172.n4.nabble.com/Questions-about-RSAKeyGenerationParameters-td1463186.html
    RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("65537"), CryptoHelper.getSecureRandom(), 2048, 64);
    gen.init(params);
    AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
    CipherParameters priv = keypair.getPrivate();
    CipherParameters pub = keypair.getPublic();
    
    System.out.println(((RSAKeyParameters) pub).getExponent());
    System.out.println(((RSAKeyParameters) pub).getModulus());
    System.out.println(((RSAKeyParameters) priv).getExponent());
    System.out.println(((RSAKeyParameters) priv).getModulus());
    
    PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(Base64.decode(key.getBytes()));    
    PrivateKey priv = KeyFactory.getInstance("RSA").generatePrivate(pkcs8);

    */
  }

  @Test
  public void testEncryptRSA() throws Exception {  
    byte[] data = PLAINTEXT.getBytes("UTF-8");
    String ciphertext = new String(Hex.encode(CryptoHelper.encryptRSA(privkey, data)));
      
    Assert.assertEquals(TEST_CIPHERTEXT, ciphertext);
  }
  
  @Test
  public void testDecryptRSA() throws Exception {
    byte[] data = Hex.decode(TEST_CIPHERTEXT);
    String cleartext = new String(CryptoHelper.decryptRSA(pubkey, data));
    
    Assert.assertEquals(PLAINTEXT, cleartext);
  }
  
  @Test
  public void testSign_Default() throws Exception {
    byte[] data = PLAINTEXT.getBytes("UTF-8");
    String sig = new String(Hex.encode(CryptoHelper.sign(CryptoHelper.DEFAULT_SIGNATURE_ALGORITHM, privkey, data)));

    Assert.assertEquals(TEST_SHA256WITHRSA_SIG, sig);
  }
  
  @Test
  public void testVerify_Default() throws Exception {
    byte[] data = PLAINTEXT.getBytes("UTF-8");
    Assert.assertTrue(CryptoHelper.verify(CryptoHelper.DEFAULT_SIGNATURE_ALGORITHM, pubkey, data, Hex.decode(TEST_SHA256WITHRSA_SIG)));
  }
  
  @Test
  public void testSign_SHA1() throws Exception {
    byte[] data = PLAINTEXT.getBytes("UTF-8");
    String sig = new String(Hex.encode(CryptoHelper.sign("SHA1WithRSA", privkey, data)));

    Assert.assertEquals(TEST_SHA1WITHRSA_SIG, sig);    
  }
  
  @Test
  public void testVerify_SHA1() throws Exception {
    byte[] data = PLAINTEXT.getBytes("UTF-8");
    Assert.assertTrue(CryptoHelper.verify("SHA1WithRSA", pubkey, data, Hex.decode(TEST_SHA1WITHRSA_SIG)));
  }

  //
  // SSH tests
  //
  
  @Test
  public void testSSHKeyBlobToPublicKey_RSA() {
    String rsapubkey = "AAAAB3NzaC1yc2EAAAABIwAAAIEA08xecCRox1yCUudqFB4EKTgfp0SkOAXv9o2OxUN8ADsQnw4FFq0qZBC5mJXlaszSHCYb/F2gG3v5iGOvcwp79JiCKx3NkMwYxHarySJi43K3ukciR5dlKv4rnStIV7SkoQE9HxSszYDki4LYnA+6Ct9aDp4cBgNs5Cscy/o3S9k=";
    
    byte[] blob = Base64.decode(rsapubkey.getBytes());
    
    PublicKey pubkey = CryptoHelper.sshKeyBlobToPublicKey(blob);
    
    Assert.assertEquals("RSA", pubkey.getAlgorithm());
    Assert.assertTrue(pubkey instanceof RSAPublicKey);
    Assert.assertEquals(new BigInteger("23", 16), ((RSAPublicKey) pubkey).getPublicExponent());
    Assert.assertEquals(new BigInteger("00d3cc5e702468c75c8252e76a141e0429381fa744a43805eff68d8ec5437c003b109f0e0516ad2a6410b99895e56accd21c261bfc5da01b7bf98863af730a7bf498822b1dcd90cc18c476abc92262e372b7ba47224797652afe2b9d2b4857b4a4a1013d1f14accd80e48b82d89c0fba0adf5a0e9e1c06036ce42b1ccbfa374bd9", 16), ((RSAPublicKey) pubkey).getModulus());
  }

  @Test
  public void testSSHKeyBlobToPublicKey_DSA() {
    String dsapubkey = "AAAAB3NzaC1kc3MAAACBAMCN5PhMDoTyfaxwAdBLyxt9QPPYKB36nfEdD/NxkeblbUHAVvTy9paesjHOzXaLFaGA7MIGOMK71OokmExothsxMNjA044TLwonwR/Uy25ig2LVpZlrlrJgrF64AV84Y6rO9UXW9WAwhuvp4a3qPX5hLdhro2a34fbOhUeWNbKvAAAAFQDD3f1U20+RA07jriYJMR8zROr8vQAAAIEArzx1ehDtiCB+gkSMzCl3eYHV7y23rmp524xgxrjL9xlboI2/L69zdpyGM9J+IVAYJARQ9fWKOfMATMu+bvuO2Q6TFvMg1NSEW8MzI+6YGKZt0+muC8gwTdogSrMA0Nh45BAigsU/tjSUYaRFUO/CbnLVulUe2O1Uta4CoraOpCEAAACBAKHWahSYbnDtepBX7tE/lNuAuHAU3Pr8pWHzXI6+SlioNhSEmclG+kr8cI0MXvAgWbKe4dR8ro9sFQY70LeBkdEbhiKOkZ7Tjt3KvxOSo5T727V2P7VuFVOqI7EDlYbysp4BeT5iB0k0qrKp+73qHSv1Py2tr0GAzIAkqufDU3Po";
    
    byte[] blob = Base64.decode(dsapubkey.getBytes());
    
    PublicKey pubkey = CryptoHelper.sshKeyBlobToPublicKey(blob);
    
    Assert.assertEquals("DSA", pubkey.getAlgorithm());
    Assert.assertTrue(pubkey instanceof DSAPublicKey);
    Assert.assertEquals(new BigInteger("00c08de4f84c0e84f27dac7001d04bcb1b7d40f3d8281dfa9df11d0ff37191e6e56d41c056f4f2f6969eb231cecd768b15a180ecc20638c2bbd4ea24984c68b61b3130d8c0d38e132f0a27c11fd4cb6e628362d5a5996b96b260ac5eb8015f3863aacef545d6f5603086ebe9e1adea3d7e612dd86ba366b7e1f6ce85479635b2af", 16), ((DSAPublicKey) pubkey).getParams().getP());
    Assert.assertEquals(new BigInteger("00c3ddfd54db4f91034ee3ae2609311f3344eafcbd", 16), ((DSAPublicKey) pubkey).getParams().getQ());
    Assert.assertEquals(new BigInteger("00af3c757a10ed88207e82448ccc29777981d5ef2db7ae6a79db8c60c6b8cbf7195ba08dbf2faf73769c8633d27e215018240450f5f58a39f3004ccbbe6efb8ed90e9316f320d4d4845bc33323ee9818a66dd3e9ae0bc8304dda204ab300d0d878e4102282c53fb6349461a44550efc26e72d5ba551ed8ed54b5ae02a2b68ea421", 16), ((DSAPublicKey) pubkey).getParams().getG());
    Assert.assertEquals(new BigInteger("00a1d66a14986e70ed7a9057eed13f94db80b87014dcfafca561f35c8ebe4a58a836148499c946fa4afc708d0c5ef02059b29ee1d47cae8f6c15063bd0b78191d11b86228e919ed38eddcabf1392a394fbdbb5763fb56e1553aa23b1039586f2b29e01793e62074934aab2a9fbbdea1d2bf53f2dadaf4180cc8024aae7c35373e8", 16), ((DSAPublicKey) pubkey).getY());    
  }

  @Test
  public void testSSHKeyBlobFingerprint() {
    
    String rsapubkey = "AAAAB3NzaC1yc2EAAAABIwAAAIEA08xecCRox1yCUudqFB4EKTgfp0SkOAXv9o2OxUN8ADsQnw4FFq0qZBC5mJXlaszSHCYb/F2gG3v5iGOvcwp79JiCKx3NkMwYxHarySJi43K3ukciR5dlKv4rnStIV7SkoQE9HxSszYDki4LYnA+6Ct9aDp4cBgNs5Cscy/o3S9k=";    
    String dsapubkey = "AAAAB3NzaC1kc3MAAACBAMCN5PhMDoTyfaxwAdBLyxt9QPPYKB36nfEdD/NxkeblbUHAVvTy9paesjHOzXaLFaGA7MIGOMK71OokmExothsxMNjA044TLwonwR/Uy25ig2LVpZlrlrJgrF64AV84Y6rO9UXW9WAwhuvp4a3qPX5hLdhro2a34fbOhUeWNbKvAAAAFQDD3f1U20+RA07jriYJMR8zROr8vQAAAIEArzx1ehDtiCB+gkSMzCl3eYHV7y23rmp524xgxrjL9xlboI2/L69zdpyGM9J+IVAYJARQ9fWKOfMATMu+bvuO2Q6TFvMg1NSEW8MzI+6YGKZt0+muC8gwTdogSrMA0Nh45BAigsU/tjSUYaRFUO/CbnLVulUe2O1Uta4CoraOpCEAAACBAKHWahSYbnDtepBX7tE/lNuAuHAU3Pr8pWHzXI6+SlioNhSEmclG+kr8cI0MXvAgWbKe4dR8ro9sFQY70LeBkdEbhiKOkZ7Tjt3KvxOSo5T727V2P7VuFVOqI7EDlYbysp4BeT5iB0k0qrKp+73qHSv1Py2tr0GAzIAkqufDU3Po";

    byte[] blob = Base64.decode(rsapubkey.getBytes());    
    byte[] fpr = CryptoHelper.sshKeyBlobFingerprint(blob);
    
    Assert.assertEquals("f9bab47184315d3fa7546043e6341887", new String(Hex.encode(fpr)));
    
    blob = Base64.decode(dsapubkey.getBytes());
    fpr = CryptoHelper.sshKeyBlobFingerprint(blob);
    
    Assert.assertEquals("4694d753ad274c18d2a286f1a326d9ac", new String(Hex.encode(fpr)));
  }
  
  @Test
  public void testSSHSignatureBlobVerify_DSA() throws Exception {
    String dsapubkey = "AAAAB3NzaC1kc3MAAACBAMCN5PhMDoTyfaxwAdBLyxt9QPPYKB36nfEdD/NxkeblbUHAVvTy9paesjHOzXaLFaGA7MIGOMK71OokmExothsxMNjA044TLwonwR/Uy25ig2LVpZlrlrJgrF64AV84Y6rO9UXW9WAwhuvp4a3qPX5hLdhro2a34fbOhUeWNbKvAAAAFQDD3f1U20+RA07jriYJMR8zROr8vQAAAIEArzx1ehDtiCB+gkSMzCl3eYHV7y23rmp524xgxrjL9xlboI2/L69zdpyGM9J+IVAYJARQ9fWKOfMATMu+bvuO2Q6TFvMg1NSEW8MzI+6YGKZt0+muC8gwTdogSrMA0Nh45BAigsU/tjSUYaRFUO/CbnLVulUe2O1Uta4CoraOpCEAAACBAKHWahSYbnDtepBX7tE/lNuAuHAU3Pr8pWHzXI6+SlioNhSEmclG+kr8cI0MXvAgWbKe4dR8ro9sFQY70LeBkdEbhiKOkZ7Tjt3KvxOSo5T727V2P7VuFVOqI7EDlYbysp4BeT5iB0k0qrKp+73qHSv1Py2tr0GAzIAkqufDU3Po";    
    byte[] blob = Base64.decode(dsapubkey.getBytes());
    
    String data = PLAINTEXT;
    String sigblobstr = "000000077373682d64737300000028b7dccad1bcb058a0e7d9383922bda8d6ff54103724ce30699e12a884d0293f10ba021333d8cebf2e";
    byte[] sigBlob = Hex.decode(sigblobstr);
    
    Assert.assertTrue(CryptoHelper.sshSignatureBlobVerify(data.getBytes(), sigBlob, CryptoHelper.sshKeyBlobToPublicKey(blob)));
  }

  @Test
  public void testSSHSignatureBlobVerify_RSA() throws Exception {
    String rsapubkey = "AAAAB3NzaC1yc2EAAAABIwAAAIEA08xecCRox1yCUudqFB4EKTgfp0SkOAXv9o2OxUN8ADsQnw4FFq0qZBC5mJXlaszSHCYb/F2gG3v5iGOvcwp79JiCKx3NkMwYxHarySJi43K3ukciR5dlKv4rnStIV7SkoQE9HxSszYDki4LYnA+6Ct9aDp4cBgNs5Cscy/o3S9k=";    
    byte[] blob = Base64.decode(rsapubkey.getBytes());
    
    String data = PLAINTEXT;
    String sigblobstr = "000000077373682d727361000000806d97905490be3e1dac74f7825e2a6c3c25693c633bb8f6413c48c9b306a6f7c2620b8fc72d70ff79ccb658ef6415d7ed2025df20967a190ce9b2ab5250c3d8f7ee0e318589e9acf212e99b2b49969c6706f76806dcb1e29d24090b89181021d8ffa401864c3621368d4fe5b89fdd76dd54019e67b014bc8a7827df2c5f59fbfe";
    byte[] sigBlob = Hex.decode(sigblobstr);
    
    Assert.assertTrue(CryptoHelper.sshSignatureBlobVerify(data.getBytes(), sigBlob, CryptoHelper.sshKeyBlobToPublicKey(blob)));
  }
  
  @Test
  public void testSSHKeyBlobFromPublicKey_RSA() {
    String rsapubkey = "AAAAB3NzaC1yc2EAAAABIwAAAIEA08xecCRox1yCUudqFB4EKTgfp0SkOAXv9o2OxUN8ADsQnw4FFq0qZBC5mJXlaszSHCYb/F2gG3v5iGOvcwp79JiCKx3NkMwYxHarySJi43K3ukciR5dlKv4rnStIV7SkoQE9HxSszYDki4LYnA+6Ct9aDp4cBgNs5Cscy/o3S9k=";    
    PublicKey key = CryptoHelper.sshKeyBlobToPublicKey(Base64.decode(rsapubkey.getBytes()));
    String blob = new String(Base64.encode(CryptoHelper.sshKeyBlobFromPublicKey(key)));    
    Assert.assertEquals(rsapubkey, blob);
  }
  
  @Test
  public void testSSHKeyBlobFromPublicKey_DSA() {
    String dsapubkey = "AAAAB3NzaC1kc3MAAACBAMCN5PhMDoTyfaxwAdBLyxt9QPPYKB36nfEdD/NxkeblbUHAVvTy9paesjHOzXaLFaGA7MIGOMK71OokmExothsxMNjA044TLwonwR/Uy25ig2LVpZlrlrJgrF64AV84Y6rO9UXW9WAwhuvp4a3qPX5hLdhro2a34fbOhUeWNbKvAAAAFQDD3f1U20+RA07jriYJMR8zROr8vQAAAIEArzx1ehDtiCB+gkSMzCl3eYHV7y23rmp524xgxrjL9xlboI2/L69zdpyGM9J+IVAYJARQ9fWKOfMATMu+bvuO2Q6TFvMg1NSEW8MzI+6YGKZt0+muC8gwTdogSrMA0Nh45BAigsU/tjSUYaRFUO/CbnLVulUe2O1Uta4CoraOpCEAAACBAKHWahSYbnDtepBX7tE/lNuAuHAU3Pr8pWHzXI6+SlioNhSEmclG+kr8cI0MXvAgWbKe4dR8ro9sFQY70LeBkdEbhiKOkZ7Tjt3KvxOSo5T727V2P7VuFVOqI7EDlYbysp4BeT5iB0k0qrKp+73qHSv1Py2tr0GAzIAkqufDU3Po";    
    PublicKey key = CryptoHelper.sshKeyBlobToPublicKey(Base64.decode(dsapubkey.getBytes()));
    String blob = new String(Base64.encode(CryptoHelper.sshKeyBlobFromPublicKey(key)));    
    Assert.assertEquals(dsapubkey, blob);    
  }
  
  @Test
  public void testSSHKeyBlobFromKeyPair_RSA() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    BigInteger modulus = new BigInteger("CBECB7A213D1EC10C40F87C4411EE98F5F8D32C4C9409D910904A41E7444812B5399FA8BF09B36014F714C66E5D2A6E9588E8E5102003F307ED29FDD9BF840067D33A8082DE57503B9846128664B9181818AD93692C00F3DE1E64D8454239D2A086B3E1FE1794B9BAF72E35110C2D058743FA2634383470B1EED86BA03E46D969EC8BCAC2F248DFCD2D26548ECA382BEFDBB577B801EFF36ACF605FB908F249083D3FFF8CFC1E0AF268268E12BAC38850B51B5F243323C0D76D2691F2E98984E8D2906C77921EA09CBDBC33DD339443F8E88885FBE860AB522565FBC337DB02A420373B775FC89CABAE1770FA2ECC7E903EE519C1A45777FF6E56C1A303299CB",16);
    BigInteger publicExponent = new BigInteger("010001",16);
    BigInteger privateExponent = new BigInteger("C396B5C2649431811B2B72228FFB2034FD86A62D0C82471E76B1D6DFC6D075BBA2A1CB27318D0CCD50EEF042B927C4238766A3A59AEFB5ABC3D82CB11709920F2742C665A1EFB4BDEFCFC28847252FD830F185C8CC141E0A5282DBD29208DE931424181FE7D8B8E607EF7F8B9F31DB371BB874FE1420F3A0FCF70103A4FC110670CD9C52A8B5BD1EA33885CDE03FBF26C6FAA82E58E0C8D2F847E24983C09B713BAE8B9CE84B8FA802612C028CB0F057488578A95C716DD81A6B13A3B7608875AFA84B06217C920B737CF4995E04D44D39E8FE3C9150CA754BB22D2DB276AA1030303EE4D1901A97D3AFB71433BFBCAEFD04516C4B219436B45C373737954851",16);
    PublicKey pubkey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    PrivateKey privkey = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
    KeyPair kp = new KeyPair(pubkey,privkey);

    byte[] blob = CryptoHelper.sshKeyBlobFromKeyPair(kp);

    byte[] referenceBlob = Base64.decode("AAAAB3NzaC1yc2EAAAEBAMvst6IT0ewQxA+HxEEe6Y9fjTLEyUCdkQkEpB50RIErU5n6i/CbNgFPcUxm5dKm6ViOjlECAD8wftKf3Zv4QAZ9M6gILeV1A7mEYShmS5GBgYrZNpLADz3h5k2EVCOdKghrPh/heUubr3LjURDC0Fh0P6JjQ4NHCx7throD5G2Wnsi8rC8kjfzS0mVI7KOCvv27V3uAHv82rPYF+5CPJJCD0//4z8HgryaCaOErrDiFC1G18kMyPA120mkfLpiYTo0pBsd5IeoJy9vDPdM5RD+OiIhfvoYKtSJWX7wzfbAqQgNzt3X8icq64XcPouzH6QPuUZwaRXd/9uVsGjAymcsAAAADAQABAAABAQDDlrXCZJQxgRsrciKP+yA0/YamLQyCRx52sdbfxtB1u6KhyycxjQzNUO7wQrknxCOHZqOlmu+1q8PYLLEXCZIPJ0LGZaHvtL3vz8KIRyUv2DDxhcjMFB4KUoLb0pII3pMUJBgf59i45gfvf4ufMds3G7h0/hQg86D89wEDpPwRBnDNnFKotb0eoziFzeA/vybG+qguWODI0vhH4kmDwJtxO66LnOhLj6gCYSwCjLDwV0iFeKlccW3YGmsTo7dgiHWvqEsGIXySC3N89JleBNRNOej+PJFQynVLsi0tsnaqEDAwPuTRkBqX06+3FDO/vK79BFFsSyGUNrRcNzc3lUhRAAAAAQAAAAABAAAAAAEA");

    Assert.assertArrayEquals(referenceBlob, blob);
  }
  
  @Test
  public void testSSHKeyBlobFromKeyPair_DSA() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("DSA");
    BigInteger p = new BigInteger("F9272971CC7F314FC8C936C4F4579485620F396D584850A092F3B9D5CF8A117B4FD6DD14E730AEE71829D019C9DB591D68010C22DFD78D988843BE76CA3CA7BE8D2ECCCC26E4285F9E7F7C54DA3687440E156FAC9D936A1F45FCA9940C35C726110E4E752EC2B9BCD30E9DED9AE07577B5FF9852E32D638BA8D505FA547B89ED",16);
    BigInteger q = new BigInteger("F79746C519DE1A9D2DF9BAB1EB01A44A9D839DDF",16);
    BigInteger g = new BigInteger("E7B9DE58A36EE0931C3BDBC3D70D9B63A856627960F7B765974A995FF0B250C26FF73D47A78CBAA60C9DD6E8A17951EBD20B2AF615C6769C49C41ECCF1922319D9E54C1212789F4F4C8EF158D35644284F77399B971DAD447CFC147F15652DC595EE3F04EF7F4DFFC305E042AD182B37BB2612C969596FE513A6AA448174A587",16);
    BigInteger y = new BigInteger("9826057402EA47BDFBE2581E9B6EEB8C7471986D5066484DB151800AF48A0C017382E2278D43E14B2898F0B3BE50CBD5EDE7BD824AAB699A143C21FCB93638BAE48D73D58013E83EBB42AB39529C6EE5AF21B95A1022A106149FDD6F1E212F936553E1FDB5F120D99F025A7CFD19485F8A310D6AF0E3258EDF3CB5C8C9D31EDD",16);
    BigInteger x = new BigInteger("BC6B3881B6F097B4C28A5E7FDEB6F47DBC022A3C",16);
    PublicKey pubkey = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
    PrivateKey privkey = keyFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
    KeyPair kp = new KeyPair(pubkey,privkey);

    byte[] blob = CryptoHelper.sshKeyBlobFromKeyPair(kp);

    byte[] referenceBlob = Base64.decode("AAAAB3NzaC1kc3MAAACBAPknKXHMfzFPyMk2xPRXlIViDzltWEhQoJLzudXPihF7T9bdFOcwrucYKdAZydtZHWgBDCLf142YiEO+dso8p76NLszMJuQoX55/fFTaNodEDhVvrJ2Tah9F/KmUDDXHJhEOTnUuwrm80w6d7ZrgdXe1/5hS4y1ji6jVBfpUe4ntAAAAFQD3l0bFGd4anS35urHrAaRKnYOd3wAAAIEA57neWKNu4JMcO9vD1w2bY6hWYnlg97dll0qZX/CyUMJv9z1Hp4y6pgyd1uiheVHr0gsq9hXGdpxJxB7M8ZIjGdnlTBISeJ9PTI7xWNNWRChPdzmblx2tRHz8FH8VZS3Fle4/BO9/Tf/DBeBCrRgrN7smEslpWW/lE6aqRIF0pYcAAACBAJgmBXQC6ke9++JYHptu64x0cZhtUGZITbFRgAr0igwBc4LiJ41D4UsomPCzvlDL1e3nvYJKq2maFDwh/Lk2OLrkjXPVgBPoPrtCqzlSnG7lryG5WhAioQYUn91vHiEvk2VT4f218SDZnwJafP0ZSF+KMQ1q8OMljt88tcjJ0x7dAAAAFQC8aziBtvCXtMKKXn/etvR9vAIqPA==");

    Assert.assertArrayEquals(referenceBlob, blob);
  }


  
  @Test
  public void testSSHSignatureBlobSign_RSA() throws Exception {
    RSAKeyPairGenerator rsakpg = new RSAKeyPairGenerator();
    RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(new BigInteger("35"), new SecureRandom(),  2048, 8);
    rsakpg.init(params);
    
    AsymmetricCipherKeyPair kp = rsakpg.generateKeyPair();
    
    RSAPrivateCrtKeyParameters privParams = (RSAPrivateCrtKeyParameters) kp.getPrivate();
    RSAKeyParameters pubParams = (RSAKeyParameters) kp.getPublic();
    
    KeySpec ks = new RSAPrivateKeySpec(privParams.getModulus(), privParams.getExponent());
    PrivateKey priv = KeyFactory.getInstance("RSA").generatePrivate(ks);
    
    ks = new RSAPublicKeySpec(pubParams.getModulus(), pubParams.getExponent());    
    PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(ks);

    byte[] data = PLAINTEXT.getBytes();
    byte[] sig = CryptoHelper.sshSignatureBlobSign(data, priv);
    
    Assert.assertTrue(CryptoHelper.sshSignatureBlobVerify(data, sig, pub));
  }
  
  @Test
  public void testSSHSignatureBlobSign_DSA() throws Exception {
    DSAKeyPairGenerator dsakpg = new DSAKeyPairGenerator();  
    DSAParametersGenerator dpg = new DSAParametersGenerator();
    dpg.init(1024, 8, new SecureRandom());
    DSAParameters dsaparams = dpg.generateParameters();
    DSAKeyGenerationParameters params = new DSAKeyGenerationParameters(new SecureRandom(), dsaparams);
    dsakpg.init(params);
    
    AsymmetricCipherKeyPair kp = dsakpg.generateKeyPair();
    
    DSAPrivateKeyParameters privParams = (DSAPrivateKeyParameters) kp.getPrivate();
    DSAPublicKeyParameters pubParams = (DSAPublicKeyParameters) kp.getPublic();
    
    KeySpec ks = new DSAPrivateKeySpec(privParams.getX(), privParams.getParameters().getP(), privParams.getParameters().getQ(), privParams.getParameters().getG());
    PrivateKey priv = KeyFactory.getInstance("DSA").generatePrivate(ks);
    
    ks = new DSAPublicKeySpec(pubParams.getY(), pubParams.getParameters().getP(), pubParams.getParameters().getQ(), pubParams.getParameters().getG());    
    PublicKey pub = KeyFactory.getInstance("DSA").generatePublic(ks);

    byte[] data = PLAINTEXT.getBytes();
    byte[] sig = CryptoHelper.sshSignatureBlobSign(data, priv);
    
    Assert.assertTrue(CryptoHelper.sshSignatureBlobVerify(data, sig, pub));
  }
  
  
  //
  // Shamir Secret Sharing Scheme
  //
  
  @Test
  public void testSSSSGF256ExpTable() {
    
    //
    // GF256 exp table with generator 2 and prime polynomial 0x11D
    // as used for the Reed Salomon of QR Code
    //
    
    short GF256_exptable[] = {
      0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 
      0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26, 
      0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 
      0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 
      0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 
      0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23, 
      0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 
      0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1, 
      0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 
      0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0, 
      0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 
      0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2, 
      0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 
      0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce, 
      0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 
      0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc, 
      0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 
      0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54, 
      0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 
      0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73, 
      0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 
      0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff, 
      0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 
      0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41, 
      0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 
      0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6, 
      0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 
      0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09, 
      0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 
      0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16, 
      0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 
      0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01
    };

    for (int i = 0; i < 256; i++) {
      Assert.assertEquals(GF256_exptable[i], SSSSGF256Polynomial.GF256_exptable[i]);
    }
  }

  @Test
  public void testSSSSGF256LogTable() {
    
    //
    // GF256 log table with generator 2 and prime polynomial 0x11D
    // as used for the Reed Salomon of QR Code
    //
    
    short GF256_logtable[] = {
      0xff, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6, 0x03, 
      0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b, 0x04, 
      0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81, 0x1c, 
      0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71, 0x05, 
      0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21, 0x35, 
      0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45, 0x1d, 
      0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9, 0xc9, 
      0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6, 0x06, 
      0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd, 0xe2, 
      0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88, 0x36, 
      0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd, 0xf1, 
      0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40, 0x1e, 
      0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e, 0x6b, 
      0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d, 0xca, 
      0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b, 0x4e, 
      0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57, 0x07, 
      0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d, 0x67, 
      0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18, 0xe3, 
      0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c, 0x11, 
      0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e, 0x37, 
      0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd, 0x90, 
      0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61, 0xf2, 
      0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e, 0x84, 
      0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2, 0x1f, 
      0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76, 0xc4, 
      0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6, 0x6c, 
      0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa, 0xfb, 
      0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a, 0xcb, 
      0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51, 0x0b, 
      0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7, 0x4f, 
      0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8, 0x74, 
      0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf, 0x01
    };

    for (int i = 1; i < 255; i++) {
      Assert.assertEquals(GF256_logtable[i], SSSSGF256Polynomial.GF256_logtable[i]);
    }
  }

  @Test
  public void testSSSSSplit_InvalidN() {  
    try {
      int n = 1;
      int k = 1;
      
      List<byte[]> secrets = CryptoHelper.SSSSSplit(PLAINTEXT.getBytes("UTF-8"), n, k);      
      Assert.assertNull(secrets);
      
      n = 256;
      k = 3;
      
      secrets = CryptoHelper.SSSSSplit(PLAINTEXT.getBytes("UTF-8"), n, k);      
      Assert.assertNull(secrets);
    } catch (Exception e) {
      Assert.assertTrue(false);
    }
  }

  @Test
  public void testSSSSSplit_InvalidK() {  
    try {
      int n = 2;
      int k = 1;
      
      List<byte[]> secrets = CryptoHelper.SSSSSplit(PLAINTEXT.getBytes("UTF-8"), n, k);      
      Assert.assertNull(secrets);
      
      n = 2;
      k = 3;
      
      secrets = CryptoHelper.SSSSSplit(PLAINTEXT.getBytes("UTF-8"), n, k);      
      Assert.assertNull(secrets);
    } catch (Exception e) {
      Assert.assertTrue(false);
    }
  }
  
  @Test
  public void testSSSSRecover() {
    
    List<byte[]> secrets = new ArrayList<byte[]>();
    
    secrets.add(Hex.decode("ab1327f622da10069f97743378dce02b6bd797ce0c4b72d1f09ead9e96f027d76625d8e2fe29c2a29ef330e194debc04"));
    secrets.add(Hex.decode("e7c83a5b4193fe10b568af7e8a5981e99f11bb3840bcc7b2ebc4233ee378a0140189c4384b389d3c379daaf3de16b6cf"));
    secrets.add(Hex.decode("d755e4d580d9f707c899b8a8ef29ee2595698b0fad871a08bd24217ae7bec109367518688460064e7124e715b69268dc"));
    secrets.add(Hex.decode("79641dc25fef964d64d2fd2d0f6e2c5040243ed93b6595285faeecb1eb8739b531b89b862d9d5356e233579b819c6348"));
    
    List<byte[]> shares = new ArrayList<byte[]>();    
    shares.addAll(secrets);
    
    //
    // Remove a random element
    //
    
    shares.remove(Math.random() * shares.size());
    
    byte[] secret = CryptoHelper.SSSSRecover(shares);
    
    Assert.assertEquals(PLAINTEXT, new String(secret));
  }
  
  @Test
  public void testSSSSRecover_DuplicateShare() {
    
    List<byte[]> secrets = new ArrayList<byte[]>();
    
    secrets.add(Hex.decode("ab1327f622da10069f97743378dce02b6bd797ce0c4b72d1f09ead9e96f027d76625d8e2fe29c2a29ef330e194debc04"));
    secrets.add(Hex.decode("e7c83a5b4193fe10b568af7e8a5981e99f11bb3840bcc7b2ebc4233ee378a0140189c4384b389d3c379daaf3de16b6cf"));
    secrets.add(Hex.decode("e7c83a5b4193fe10b568af7e8a5981e99f11bb3840bcc7b2ebc4233ee378a0140189c4384b389d3c379daaf3de16b6cf"));
    
    byte[] secret = CryptoHelper.SSSSRecover(secrets);
    
    Assert.assertNull(secret);
  }

  //
  // PGP
  //
  
  @Test
  public void testPGPKeysFromKeyRing() throws IOException {
    String keyring = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
    "Version: GnuPG v1.4.6 (Darwin)\n" +
    "\n" +
    "mQGiBFDfB/cRBADE6Ee9TtA961l9dtQYauMJ5LCo/YWhz1dft0KmqI7k7sKWLKfz\n" +
    "OhTOnT61fwEhHdHlOwQdCD7EpeKEGfSWxeajdtuKE9/QP+PJalGA5s48XrdqfrkA\n" +
    "QJkK+77atAixoi4r9ozljP9vXHIltAlDkaoDdRZcVe1J+pW0Kw7AGHvA/wCgvwKI\n" +
    "cuyep7ViScOXkCwZ6+7eFqsD/RLzBN7mb2h+yEY+XvFqQPvenvZS/sw3JZf/cY4u\n" +
    "Mi+FzkTb0BB1X75skLvvO1JYpraGphSB075LzHW/ohKQacaY74rpxpxIZz9EjHTa\n" +
    "JSmLTT6SBQMlX+LSNwHQYQWPzitQ1os6LRmgiE5pfZGlvOLyC+sHeDxUzPEl1069\n" +
    "NqXEA/9r1e4eAu7HLED2XIP3fgOV/kkDrJC1EX0N8Ck/ON0S+hJYK1b0W6TKWdN6\n" +
    "tVH/OL37tymsfI+qSEhKNVe2sDcybG6trJj528puJdVpb2wqMwbCdxx7Cr3wX61x\n" +
    "jFQJQwqyXCWakPbWfhxvron62/RamTmf2KSMgf79yv29WOE5+7QbTWFzdGVyU2Vj\n" +
    "cmV0R2VuZXJhdG9yVGVzdCMxiGYEExECACYFAlDfB/cCGwMFCQABUYAGCwkIBwMC\n" +
    "BBUCCAMEFgIDAQIeAQIXgAAKCRD3wPNFoZ4UAw4KAJ47rbv6e5oy0p0qOu1YjCUn\n" +
    "7Sm+PACePylkvbBc7jkoJrc8n+2ZJRBL/vK5Ag0EUN8H/BAIAJdLjwQf2NwhkW/9\n" +
    "h7wV2luiCvzwPxhvOytPM9ZtckyK3f9Biam29uZt2P/EgYAlEb7odHuQ8rYquuM8\n" +
    "rZ5bNMY4SlgDfGTAYIPTC6r3oPoxVzg3bfL/VfAQWZTz7gsNexBqoxmCEGG8cbp4\n" +
    "/YYTArrW0pdAjIve/H2Wb3C6+ntbPXq60BJTlpbJXh3CPL95jUF0bJbt/WwOdE5r\n" +
    "TQ0WKikTY8RV18XekJAHRT0PrHjecAsvY1NOXlQJGbJes7unQDdCkQ2RRbg4Vdt4\n" +
    "SHSdKunIIxbLEOj6HuJyvkbQ65yHSnfLtoS2XpNe9ft/+ZtXjHsr01XE0cqbrSwf\n" +
    "GqO9068AAwcIAJS0myak/K/rqwC/MGQ7U4OEovVY/n9mpPwQKN0bUSU/uDLKy3JW\n" +
    "vqO5vvWr9iWqyq/GfPeJ2HZ/kvGiyR7Qy/7gh8Q8yDLn9qrz06ewd9G3Tyxj8n80\n" +
    "re0vRopQsyKNLhtC5ZEtq9Q3yfqt7ib8sf8hLlxCzpDNlIUdbTqpFcnfxc8p7aQB\n" +
    "4lqrT32fGtYtDjUt86VzT4LCRNTgMOxPF5iYOiOzB0iX7oPoCqGFxl0ZTvxqMpgV\n" +
    "/hr8CWJlW3AAcc3l2HONQe/Gg5nrTtm72i0vH8n8F/GgfZmU8KJc7c7cFhtGDTWV\n" +
    "dkNjrqBtuiuKpZcwf14stCFfAmZXeYZ+xTCITwQYEQIADwUCUN8H/AIbDAUJAAFR\n" +
    "gAAKCRD3wPNFoZ4UA9oLAJsFL3JRi2zHxwutO7PqMfItSub0cACgs7BQ3nPA5DP+\n" +
    "Hhr3Xwsu7+wSOKk=\n" +
    "=H4+g\n" +
    "-----END PGP PUBLIC KEY BLOCK-----\n";
    
    List<PGPPublicKey> pubkeys = CryptoHelper.PGPPublicKeysFromKeyRing(keyring);
    
    Assert.assertEquals(2, pubkeys.size());
    
    Set<Long> keyids = new HashSet<Long>();
    
    for (PGPPublicKey key: pubkeys) {
      keyids.add(key.getKeyID());
    }
    
    Assert.assertTrue(keyids.contains(0xf7c0f345a19e1403L));
    Assert.assertTrue(keyids.contains(0x60744f29e427916cL));
  }
  
  //
  // SSHAgent
  //  
}
