# oss


Open Secret Server

OSS is a webapp which manages secrets (mainly AES wrapping keys) on behalf of applications which query the OSS at launch time to retrieve a master AES wrapping key with which all their sensitive data has been encrypted.

OSS itself has a master wrapping key with which it encrypts all the secrets it manages.

The OSS wrapping key is generated and encrypted with multiple PGP keys. Optionally, the wrapping key can be split using a Shamir Secret Sharing Scheme so that k splits among n are needed to reconstruct the master wrapping key.

Calls to the OSS are authenticated using signatures generated by an SSH agent.

The dialogue with the SSH agent is established using the JUDS 0.95 library (see https://github.com/mcfunley/juds).
To correctly install the JUDS library, you may have to install the `lib32-gcc-libs` library.

Follow those steps to set up an OSS instance:

## 1. Build OSS

	gradle buildjuds
	gradle assemble

Note: On OSX you may have to run the following first:

        sudo ln -s /System/Library/Frameworks/JavaVM.framework/Headers /System/Library/Frameworks/JavaVM.framework/Home/include

## 2. Generate a master secret

To build OSS client run 

  gradle ossClientJar

### 2.1. Export your PGP keyring (we use gpg in the example below)

	gpg --export -a > pubring.gpg

### 2.2. Identify the key ids with which you wish to encrypt the master secret. The keys MUST be capable of encryption (i.e. ElGamal or RSA).

	gpg --list-keys

	pub   1024D/4E06E786 2012-12-31
	uid                  OSS#1
	sub   2048g/3812C9B7 2012-12-31

in the above example, key ID '3812C9B7' can be used, but not '4E06E786'.

### 2.3. Generate the master secret

First generate the master secret and encrypt it with a safety key. Do that on an unconnected machine you trust.

	java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSGenMasterSecret ./pubring.gpg xxxxxxxx 1 > xxxxxxxx.oss

The file 'xxxxxxxx.oss' contains the following content:

	[c37e2815xxxxxxxx] <- ID of key used to encrypt the following PGP MESSAGE

	-----BEGIN PGP MESSAGE-----
	Version: BCPG v1.47

	hQIOA8N+KBU4Esm3EAf8D8e7qTUMTv5flSL3AxHOwc0MrJH/wlRT2SIgRZWYyNFE
	i4VVanSVdoIt2DBQbmyzeREDGuAGJu7zF+oBPNDHUWBGqT+Rk/DGjLiWzFzptPV0
	sEXla2JQ2O5ecqAVQMo0LIWkbLChFRPCearuUj+eyPY9HIMGBF2JuN0NU8zuZrLS
	cnsB1Ua/XAljs0v1ckmPem4jvX04I59Yr++F+8JACFQlDRj4tm63HcHSQ/fe+YN5
	m4clwKvjrfi+4cvntw6Km15SyBl1bJ+CvIXgj8zNPHyELy+F5VEAyb5wqvMS4E7w
	W7h+Ttey4nSh6JXzQPm2h8pnxOBuhaYWg96LvTxm/wf/RQOUYSy1TqVBUhsb5B0+
	rcHTZ7Hlz8joEUL7OHqzLer4yyJhNI4JYfoThba14rVFk/RDpWBnQLbWOT/oJ4tr
	rHu299YH3gJlqFtgXhx8Ra5ZTukdyrSrOxRldN3RRVaFoM5b+GO/kfyADhu7nyul
	aTqRgLdQGmtCZjUiuH9mxrNDfIeXj8sqIXbV2MnRJxhkG8jocCHewuBmgMYPkfdX
	O+9BD1eigJdOHWEedf9c3qexq46jq8HkOF5wZdENPhBYfXKVbQcQjk11TIuPEYV2
	Lt0QkhDFoS4o4y6xcWsDful8FpaC6ii8mHbgfiwQBYpB+pYloiCNNlP+hYdEprMZ
	CtLDaQFE68J2wV9/bYuIa0p8bimRKy6SUi9Rh0qf7Yalnrld/emB020/OZO/OAlK
	DJUpHhuPPvuHeyWzJkbpqh5iO6Wv7GZiyPNp8hGWuuGNHmBPXtJ5DDruaoP31NhZ
	Dtp3CneDKBi/
	=x3RL
	-----END PGP MESSAGE-----

Put this in a VERY SAFE place, this should only be used when rekeying the OSS instance or when re-splitting the master secret.

The secret should now be split among N persons with K splits needed to initialize the OSS instance.

	gpg -d xxxxxxxx.oss | java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSSplitMasterSecret ./pubring.gpg hhhhhhhh0,hhhhhhhh1,....,hhhhhhhhN K

The output will contain N + 1 PGP messages. Each one should be given to the owner of the matching key.

NOW DELETE xxxxxxxx.oss in a secure way (using 'srm') (make sure it has been put in a safe plave first...).


## 3. Launch an OSS instance, we'll use the jettyRun task but feel free to deploy build/libs/oss.war in your favourite application server

You need to set the following system properties prior to launching OSS (or modify WEB-INF/web.xml).

oss.keystore.dir	Directory where secrets and ACLs will be stored (MUST exist prior to launching OSS)
oss.init.sshkeys	Comma separated list of SSH key fingerprints authorized to initialize the OSS instance
oss.gensecret.sshkeys	Comma separated list of SSH key fingerprints authorized to generate new secrets (256 bits) in the OSS instance
oss.putsecret.sshkeys	Comma separated list of SSH key fingerprints authorized to store external secrets in the OSS instance
oss.acl.sshkeys		Comma separated list of SSH key fingerprints authorized to read and modify ACLs
oss.max.secret.size     Maximum size (in bytes) of external secrets that can be stored in the OSS (defaults to 32 bytes)
oss.token.ttl		Delay in ms during which authentication tokens will be considered valid (defaults to 15000 ms)

	JAVA_OPTS="-Doss.keystore.dir=/var/tmp/oss-test -Doss.init.sshkeys=... -Doss.gensecret.sshkeys=... -Doss.putsecret.sshkeys=... -Doss.acl.sshkeys=..." gradle jettyRun

When using oss with Gradle version above of 7.0, `gradle jettyRun` is not available anymore. However you can still download a version of jetty compatible with the jdk8: https://search.maven.org/artifact/org.eclipse.jetty/jetty-runner. Download the jetty jar file of a version `9.X`. 

Then write a `run.sh` file which would look like: 

```sh
## run.sh file 
export JAVA_OPTS="-Doss.keystore.dir=/var/tmp/oss-test -Doss.init.sshkeys=46:94:d7:......:26:d9:ac -Doss.gensecret.sshkeys=46:94:d7:......:26:d9:ac -Doss.putsecret.sshkeys=46:94:d7:......:26:d9:ac -Doss.acl.sshkeys=46:94:d7:......:26:d9:ac"
echo "runing OSS war "
java $JAVA_OPTS -jar jetty/jetty-runner-9.4.49.v20220914.jar --port 8080 --host 127.0.0.1 --path /oss build/libs/oss-1.0.1.war
```

And finally use this `run.sh` to start oss

## 4. Have K persons send their master secret split to OSS using the following command:

The SSH keys of those K persons MUST be present in 'oss.init.sshkeys' and their SSH agent must be running and contain the matching private key.

in the following commands, OSS_URL should be replaced by the root URL of your OSS instance (in case of jettyRun, OSS_URL = http://127.0.0.1:8080/oss)

	gpg -d hhhhhhhhX | java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSInit OSS_URL

The first K-1 persons should have an informative message stating that more secrets are needed.

The last person will have a message stating that the OSS was initialized successfully.


## 5. Generate a new secret

	java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSGenSecret OSS_URL foo.bar.mysecret


## 6. Retrieve the ACLs for the secret

	java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSGetACL OSS_URL foo.bar.mysecret

(ACLs should be empty)


## 7. Add keys to the ACL for foo.bar.mysecret

	java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSAddACL OSS_URL foo.bar.mysecret SSH_FPR_1,SSH_FPR2,...

You can later remove SSH fingerprints from ACLs using OSSRemoveACL instead of OSSAddACL.


## 8. Retrieve secret

	java -cp build/lib/oss-client.jar com.geoxp.oss.client.OSSGetSecret OSS_URL foo.bar.mysecret


## 9. Put an external secret

	cat SUPER_SECRET_DATA | java -cp build/lib/oss-client.jar com.geoxp.oss.client.OSSPutSecret OSS_URL secret.name

instead of being plaintext accessible via 'cat', data should have been encrypted using a PGP public key of a user listed in 'oss.putsecret.sshkeys'.


## 10. Wrap secret data with a secret contained in OSS

	cat SUPER_SECRET_DATA | java -cp build/lib/oss-client.jar com.geoxp.oss.client.OSSWrap OSS_URL foo.bar.mysecret

instead of being plaintext accessible via 'cat', data should have been encrypted using a PGP public key of a user listed in 'oss.putsecret.sshkeys'.


## 11. Rekeying OSS secrets

In case you have a doubt concerning the secrecy of the master secret generated at step 2, you need to generate a new one and rekey all secrets and ACLs currently managed by your OSS instance.

### 11.1 Copy all data under 'oss.keystore.dir' on a machine you will disconnect from any network.

### 11.2 Generate a new master secret and have the xxxxxxxx.oss files of both the new and current master secrets handy on the machine you used at 11.1

### 11.3 On this machine run:

	mkfifo -m 0600 current-master
	mkfifo -m 0600 new-master
	gpg -d current-xxxxxxxx.oss > current-master & 
	gpg -d new-xxxxxxxx.oss > new-master &
	find oss.keystore.dir -name '*.secret' -o -name '*.acl' | java -cp build/libs/oss-client.jar com.geoxp.oss.client.OSSRekey current-master new-master .rekeyed

make sure you securely delete the two '.oss' files and the '.secret' and '.acl' files under 'oss.keystore.dir' using srm prior to reconnecting the machine to a network.

You can now strip the '.rekeyed' suffix from all files in 'oss.keystore.dir', this is your new OSS managed data.

Launch an instance of OSS using the new master secret, you're done, and hopefully still safe. If you have a doubt on any secret, please regenerate it.

If you had data wrapped with a secret you no longer trust, regenerate it, rewrap all data (possibly change it first if feasible, i.e. passwords).
