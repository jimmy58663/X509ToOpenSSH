# X509ToOpenSSH
PowerShell functions to convert Windows X509Certificate2 objects to OpenSSH public key format to use for SSH authentication.

OpenSSH keys are formatted with 3 parts: Algorithm, Key, Comment (each part is separated by a space)
The Algorithms are represented by the following strings: ssh-dss, ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519
The Key is made up of 3 parts which are each broken down into length and data.
	Part 1: Algorithm, 4 bytes for length, and then the algorithm used based on the strings above as well
			Example: ssh-rsa
				Length: 00000007 - 4 bytes saying the next piece of data is 7 bytes in length
				Data: 7373682d727361 - 'ssh-rsa' converted from a string to a byte array and then hex values
  Part 2: Exponent, 4 bytes for length, and then the RSA exponent value which is commonly 65537
			Example: 65537
				Length: 00000003 - 4 bytes saying the next piece of data is 3 bytes in length
				Data: 010001 - 65537 converted to hexadecimal
  Part 3: Modulus, 4 bytes for the length, and then the modulus of the public key. 1 additional byte is added to the lenth and prepends the modulus value with 00
			Example: wrq57U..idQ== (2048 bit key)
				Length: 00000101 - 4 bytes saying the next piece of data is 257 bytes in length ((2048 / 8) + 1)
				Data: 00c2ba..762275 - the modulus converted to bytes and then hexadecimal preprended by 00
The Comment is made up of whatever string information you want to put there. In this function we use the X.509 certificate thumbprint and subject. Spaces are allowed in the comment.

A large majority of the above information I pulled from https://www.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/.
