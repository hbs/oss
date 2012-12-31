package com.geoxp.oss.client;


public class OSSGenSecret {
  public static void main(String[] args) throws Exception {
    if (3 != args.length) { 
      System.err.println("Usage: OSSGenSecret OSS_GEN_SECRET_URL SECRET_NAME SSH_SIGNING_KEY_FINGERPRINT");
    }
    
    OSSClient.genSecret(args[0], args[1], args[2]);
    
  }
}
