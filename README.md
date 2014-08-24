## SHAAAAAAAAAAAAA

_**Do you have the latest SHA??**_

Your SSL certificate was signed using a one-way hashing algorithm when it was created. It was probably SHA-1.

Which is too bad, because **SHA-1 is considered weak**, and **SHA-2 is the replacement**.

Here are 3 ways to quickly test your site's cert:

* Visit [shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com) (quick, simple)
* Visit [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html) (comprehensive)
* Run this repo's `./bin/shaaaaaaaaaaaaa` script.

This repository contains the code for [shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com).

#### Do I have to care?

**Yes.** Be a part of the solution.

SHA-1 was [broken in 2005](https://www.schneier.com/blog/archives/2005/02/sha1_broken.html), and in 2014 [it's estimated to cost $1-2M](https://www.schneier.com/blog/archives/2012/10/when_will_we_se.html) to forge a SHA-1 certificate. That's a tiny amount of money.

Eventually, browsers and OSes will distrust SHA-1:

* In 2013, [Microsoft deprecated SHA-1](http://blogs.technet.com/b/pki/archive/2013/11/12/sha1-deprecation-policy.aspx) for Windows and Internet Explorer.
* In 2014, [the Chromium team deprecated SHA-1](https://groups.google.com/a/chromium.org/forum/#!msg/blink-dev/2-R4XziFc7A/YO0ZSrX_X4wJ) for Chrome.

They've promised dire consequences in 2016 and 2017, but the only way they'll be able to follow through on their threat is if enough people update their certs ahead of time.

The last time this happened was with [MD5](http://en.wikipedia.org/wiki/MD5). MD5 was first shown to be weak in **1996**, and Chrome wasn't able to remove MD5 support until **[December 2011](https://code.google.com/p/chromium/issues/detail?id=101123#c15)**.

It's 2014, and the overwhelming number of certificates in the wild today -- including those of leaders like Google -- are SHA-1.

If you're using a SHA-1 cert, take a few minutes and generate a new one with SHA-2.

#### How do I make a SHA-2 certificate?

When you're generating your certificate request, include the `-sha256` parameter:

```
openssl req -new -sha256 -key my-private.key -out mydomain.csr
```

That will instruct the certficate authority to use SHA-256 (a form of SHA-2) when generating your certificate.

For more information on generating and installing a certificate, see:

* this author's [guide to setting up HTTPS](https://konklone.com/post/switch-to-https-now-for-free#generating-the-certificate)
* this author's [nginx configuration](https://gist.github.com/konklone/6532544) that produces [this SSL Labs rating](https://www.ssllabs.com/ssltest/analyze.html?d=konklone.com)

## Author

This is a tiny Node app and CLI tool by [Eric Mill](https://twitter.com/konklone). Released under an [MIT License](LICENSE).
