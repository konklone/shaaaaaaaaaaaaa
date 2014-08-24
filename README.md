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

Eventually, browsers and OSes will distrust SHA-1:

* In 2013, [Microsoft deprecated SHA-1](http://blogs.technet.com/b/pki/archive/2013/11/12/sha1-deprecation-policy.aspx) for Windows and Internet Explorer.
* In 2014, [the Chromium team deprecated SHA-1](https://www.ssllabs.com/ssltest/analyze.html?d=konklone.com) for Chrome.

They've promised dire consequences in 2016 and 2017, but the only way they'll be able to follow through on their threat is if enough people update their certs ahead of time.

The last time this happened was with [MD5](http://en.wikipedia.org/wiki/MD5). MD5 was first shown to be weak in **1996**, and Chrome wasn't able to remove MD5 support until **[December 2011](https://code.google.com/p/chromium/issues/detail?id=101123#c15)**.

## Author

This is a tiny Node app and CLI tool by [Eric Mill](https://twitter.com/konklone). Released under an [MIT License](LICENSE).
