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
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class OSSSplitMasterSecret {
  public static void main(String[] args) throws Exception {
    
    if (3 != args.length) {
      System.err.println("Usage: OSSSplitMasterSecret PATH_TO_PUBRINGS PGP_KEY_IDS K\nSecret to split (from previous OSSGenMasterSecret/OSSSplit with k=1) to be fed as stdin.");
      System.exit(1);
    }
    
    String[] keyids = args[1].split(",");
    
    List<String> pgpkeyids = new ArrayList<String>();
    
    for (String keyid: keyids) {
      pgpkeyids.add(keyid);
    }
    
    String[] pubrings = args[0].split(",");

    List<String> pgppubrings = new ArrayList<String>();
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    
    for (String pubring: pubrings) {
      InputStream is = new FileInputStream(pubring);
      baos.reset();
      
      do {
        int len = is.read(buf);
        
        if (len < 0) {
          break;
        }
        
        baos.write(buf, 0, len);
      } while (true);
      
      is.close();
      baos.close();
    
      pgppubrings.add(new String(baos.toByteArray(), "UTF-8"));
    }

    //
    // Read secret from stdin
    //
    
    ByteArrayOutputStream secret = new ByteArrayOutputStream();
    
    do {
      int len = System.in.read(buf);
      
      if (len < 0) {
        break;
      }
      
      secret.write(buf, 0, len);
    } while (true);
    
    secret.close();

    Map<String,String> shares = OSSClient.genMasterSecret(secret.toByteArray(), pgppubrings, pgpkeyids, Integer.valueOf(args[2]));
    
    for (Entry<String,String> entry: shares.entrySet()) {
      System.out.println();
      System.out.println("[" + entry.getKey() + "]");
      System.out.println();
      System.out.println(entry.getValue());
    }
  }
}
