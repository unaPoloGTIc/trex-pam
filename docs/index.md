---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

#layout: home

layout: page
title: "Trex-Security Demo"
permalink: /
---

# Trex PAM module demo:

## In a few words:
The module allows for a :
* secure
* One Time Password
* offline

Login to any device capable of running
* PAM
* GPG

No connectivity or clock synchronization needed.  
For more details, see the readme of the repository at:  
<https://github.com/unaPoloGTIc/trex-pam>

## Running the demo:

### Setup
* Get the image:
 ```
 docker pull trexsec/pam-demo:latest
 ```
* Run the container:
 ```
 docker run -td --rm --network host --name trex-demo trexsec/pam-demo:latest
```

* SSH into the demo: (replace `device-address` with the actual address)
```
ssh -o StrictHostKeyChecking=no docker@device-address -p2222
```
* Follow the instructions printed.
* Password for users `docker`, `root` is `1234`

### Once convinced that:
* The container does not access the Internet
* The container does not need to sync the time
* The container does not hold any secret key of value (optional temp. HTTPS key only).
* To login, a GPG message must be decrypted
* The message is only used once
* The message can also be obtained as a QR code

### Proceed to the demo of the proprietary product:

#### Submit the form:
* We will not contact you without your consent.
* We will never share your information with any party.

<form>
<textarea rows="15" cols="70" maxlength="2000" name="challange" placeholder="Paste your challange here." required>
</textarea><br>  
<input type="email" name="email"><br>  
<input type="checkbox" name="retain">Keep my email address and contact me once at most.<br>
<input type="submit"  value="Get OTP">
<input type="reset">
</form>

WIP

## A full demo includes:
* Full on premise control of the keys used.
* Control and configure users and permissions.
* See logs with login attempts and history.
* See other front-ends in action.

