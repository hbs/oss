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
