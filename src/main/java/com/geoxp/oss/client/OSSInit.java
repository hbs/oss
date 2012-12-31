package com.geoxp.oss.client;


public class OSSInit {
  public static void main(String[] args) throws Exception {
    
    if (2 != args.length) {
      System.err.println("OSSInit OSS_INIT_URL SSH_SIGNING_KEY_FINGERPRINT");
      System.exit(1);
    }

    OSSClient.init(args[0], args[1]);    
  }
}
