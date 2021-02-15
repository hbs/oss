/*
 * Copyright 2012-2021 Mathias Herberts
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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.MasterSecretGenerator;
import com.geoxp.oss.OSSException;

public class OSSRekey {

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      throw new OSSException("Usage: OSSRekey CURRENT_MASTER_SECRET_NAMED_PIPE NEW_MASTER_SECRET_NAMED_PIPE SUFFIX");
    }

    String suffix = args[2];

    //
    // Read current and new master secrets
    //

    byte[] buf = new byte[1024];

    ByteArrayOutputStream currentMasterSecret = new ByteArrayOutputStream();
    ByteArrayOutputStream newMasterSecret = new ByteArrayOutputStream();

    InputStream is = new FileInputStream(args[0]);

    while (true) {
      int len = is.read(buf);
      if (len < 0) {
        break;
      }
      currentMasterSecret.write(buf, 0, len);
    }

    is.close();

    is = new FileInputStream(args[1]);

    while(true) {
      int len = is.read(buf);
      if (len < 0) {
        break;
      }
      newMasterSecret.write(buf, 0, len);
    }

    is.close();

    //
    // unwrap both current and new master secrets with the internal control KEK
    //

    byte[] currentMS = CryptoHelper.unwrapAES(
        MasterSecretGenerator.getMasterSecretWrappingKey(),
        currentMasterSecret.toByteArray());
    byte[] newMS = CryptoHelper.unwrapAES(
        MasterSecretGenerator.getMasterSecretWrappingKey(),
        newMasterSecret.toByteArray());

    //
    // loop on a list of secret files to rekey, provided on stdin
    //

    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    long nano = System.nanoTime();
    int count = 0;

    while (true) {
      String line = br.readLine();
      if (null == line) {
        break;
      }

      //
      // Read data wrapped with current master secret
      //

      baos.reset();
      is = new FileInputStream(line);
      while (true) {
        int len = is.read(buf);
        if (len < 0) {
          break;
        }
        baos.write(buf, 0, len);
      }
      is.close();

      //
      // Unwrap data with current master secret
      //

      byte[] data = CryptoHelper.unwrapBlob(currentMS, baos.toByteArray());

      if (null == data) {
        throw new OSSException("Unable to unwrap data in '" + line + "'");
      }

      //
      // Wrap data with new master secret and write it to the suffixed file
      //

      OutputStream os = new FileOutputStream(line + suffix);

      os.write(CryptoHelper.wrapBlob(newMS, data));
      os.close();
      count++;
    }

    nano = System.nanoTime() - nano;

    System.out.println("Rekeyed " + count + " files in " + (nano / 1000000.0) + " ms.");
  }
}
