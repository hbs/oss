package com.geoxp.oss.client;

import org.bouncycastle.util.encoders.Hex;

import com.geoxp.oss.OSSException;

public class OSSGetSecret {
  
  public static void main(String[] args) throws Exception {
    if (3 != args.length) { 
      throw new OSSException("Usage: OSSGetSecret OSS_GET_SECRET_URL SECRET_NAME SSH_SIGNING_KEY_FINGERPRINT");
    }

    byte[] secret = OSSClient.getSecret(args[0], args[1], args[2]);
    
    System.out.println("Secret = " + new String(Hex.encode(secret)));
  }
}
