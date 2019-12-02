---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

#layout: home

layout: page
title: "Trex-Security Demo"
permalink: /
---

# In a few words:
The module allows for a:
* Secure
* Single use password
* Offline

Login, to any device capable of running:
* PAM
* PGP

No connectivity, secret key or clock synchronization needed.  
For more details, see the readme of the repository at:  
<https://github.com/unaPoloGTIc/trex-pam>

# Running the demo:

## Setup
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

## Once convinced that:
* The container does not access the Internet
* The container does not need to sync the time
* The container does not hold any secret key of value (optional temp. HTTPS key only).
* To login, a PGP message must be decrypted
* The message is only used once
* The message can also be obtained as a QR code

## Proceed to the demo of the proprietary product:

### Submit the form:

WIP:

<script>
function getresp() {
var req=new XMLHttpRequest();
req.open("POST", "https://api.github.com/user", true);
//set in server: req.setRequestHeader("Access-Control-Allow-Origin", "demo.trex-security.com")
req.setRequestHeader("Content-type", "multipart/form-data")
req.onreadystatechange = function() {
 if (this.readyState == 4 && (this.status == 200 || true)) {
    document.getElementById("chalid").value =
    this.responseText;
  }
};
req.send(document.getElementById("chalid").value);
}
</script>

<form>
<fieldset>
<legend>Demo OTP</legend>
<textarea id="chalid" rows="15" cols="65" maxlength="2000" name="challange" placeholder="Paste your challange here." required>
</textarea><br>  
<button type="button" onclick="getresp()">Get an OTP</button>
<input type="reset">
</fieldset>
</form>
<br>
<p><span id="otp"></span></p>
<br>
# A full demo includes:
* Full on-premise control of the keys used.
* Control and configure users and permissions.
* See logs with login attempts and history.
* See other front-ends in action.

