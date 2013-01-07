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

public class OSSPutSecret {
  public static void main(String[] args) throws Exception {
    
    if (args.length < 2) {
      System.err.println("Usage: OSSPutSecret OSS_URL SECRET_NAME [SSH_SIGNING_KEY_FINGERPRINT]");
      System.exit(1);
    }

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

    String sshkey = args.length > 2 ? ("".equals(args[2]) ? null : args[2]) : null;
    OSSClient.putSecret(args[0], args[1], secret.toByteArray(), sshkey);    
  }
}
