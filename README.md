# Trex PAM module:

## A PAM module that enables PAM to authenticate a user using a GPG key-pair.

The module will present a challenge to the user, encrypted using his public key.
User is then required to use his private key to decrypt,
extract the correct response and present it to the authenticating app.

User has 1 attempt to provide the correct response and must do so within 10 minutes.
Failure requires a start-over with a new challenge and response.

## Using the module:

Place the binary (.so) anywhere readable by your app.  
(Your distribution probably has a location for PAM modules)  

### Configure PAM:
Create/edit a config file for PAM (usually under /etc/pam.d/)  
Say /etc/pam.d/sshd  
Add to it something like:  
auth	required	/path/to/trex-module.so  

### Configure users:
For each user to utilize the module create ~username/.auth_gpg  
Place in it a line instructing the module:  
<email to encrypt to> <trust | notrust> <email to sign as | nosign> \<webQR specification\> [https server key] [https server certificate]  

trust\notrust indicates to GPG whether to use the key if not known to be trusted or not.  
nosign means not to sign the challenge. See security considerations below.  
webQR will present the challenge as an QR code viewable via a browser. It can be one of these 4 strings:  
* webQrAuthTls - require http basic auth and use TLS  
* webQrNoAuthTls - skip http basic auth but use TLS  
* webQrAuthNoTls - require http basic auth and don't use TLS  
* webQrNoAuthNoTls - skip http basic auth and skip TLS  
* any other string will disable presenting the QR via a browser.  

If TLS was requested, 2 more parameters are needed.  
A path to the key file and a path to the certificate to use for HTTPS.  

Now you can ssh user@host and follow the displayed instructions.  

## Security considerations:
The module generates a random challenge for every attempted login.  
The correct (randomized) response must be entered within 10 minutes and on the first attempt.  
This is to prevent replay attacks.  
Using the module with PAM's "optional" will provide no added security.__
It's best if the corresponding secret key is nowhere near the machine.__

## Protect the module, pam config files, .auth_gpg file and the private key in all the usual ways.  

In particular, reusing the GPG keys for other purposes is strongly discouraged.  
The main reason being that in normal usage user is expected to decrypt a challenge presented to him.  
In case of a man-in-the-middle attack, the attacker might present to the user a previously captured message.  
Harmless in case of a previous challenge, but possibly lethal in case of a secret email encrypted with the same key.  

Formally, the challenge may be published as follows:  
After the login attempt: even after failure, the module will no longer accept the corresponding response.  
Before the login attempt: if you are sure that your private key is private and cannot be cracked within 10 minutes.  
Note that even if an attacker steals the private key  
or otherwise obtains a correct response he still has to take over the session of the user,  
SSH session or keyboard session.  

The module allows to protect the challenge QR in 2 ways:  
HTTP basic auth: the SSH session will protect the randomized credentials.  
In case of an attacker who tries to steal the QR via the browser but can't decrypt SSH traffic or sniff web traffic.  
HTTPS: using a key and certificate trusted by the user.  
In case of an attacker able to target the network and read/modify packets.  

sign/nosign: signing the challenge may prevent an attacker from presenting to the user a fake challenge.  
(If the attacker can't steal the signing key.)  
If unsigned, the attacker might fool the user to decrypt a message encrypted by the attacker.  
In which case the attacker learns nothing new.  

### Replay attacks:
As stated above, a reused response will not be accepted.  
Except in the case in which the new session's random response is the same.  
Currently the response is a 10 chars long string consisting of lowercase, uppercase and digits.  
If your platform has good randomness, expect that to happen at a rate of about 1 in sqrt(64^10) (about 1B+)  

### MITM attacks:
A man in the middle that is already capable of presenting itself to the user as the system will  
be able to present the response and proxy the modified session to the unsuspecting user.  
In case of a keyboard login, it means running code on the machine with at least as much privileges as the user.  
Meaning the user was already compromised.  
In case of SSH login, it means pulling a MITM attack between the user and the SSH server.  
Meaning again that the attacker already had the ability to run code on the server or decrypt+modify SSH traffic.   

## In any manner,
this scheme is no more secure than your keys, randomness in your machine  
and every other limitation that applies to crypto in the real world.  

## Note about the tests:
Some unit-tests are provided.  
Setting your environment so that they will pass may take a while,  
and may be incompatible with your real world needs.  

Some more unit-tests are not yet provided and are hinted to in the test file.  

Valgrind tests are not currently provided since there are 1k+ false positives.  
(Valgrind has no way of knowing that memory was allocated/initialized so it complaints)  
If you think there is a leak or illegal memory access, please open an issue.  
