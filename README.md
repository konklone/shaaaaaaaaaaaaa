## SHAAAAAAAAAAAAA

_**Do you have the latest SHA??**_

Your SSL certificate was signed using a one-way hashing algorithm when it was created. It was probably SHA-1.

Which is too bad, because **SHA-1 is dangerously weak**, and **SHA-2 is the replacement**.

Test your site's certificate by visiting [shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com):

> https://shaaaaaaaaaaaaa.com/check/yourdomain.com

You can also use this repo's `./bin/shaaaaaaaaaaaaa` script to get an answer on the command line, or visit the excellent [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html) for a far more comprehensive review of your SSL configuration.

This repository contains the code for [shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com). It depends on `openssl`.

#### Do I have to care?

**Yes.** Go [read the website](https://shaaaaaaaaaaaaa.com/)and be a part of the solution.

#### How do I make a SHA-2 certificate?

When you're generating your certificate request, include the `-sha256` parameter:

```
openssl req -new -sha256 -key my-private.key -out mydomain.csr
```

That will instruct the certificate authority to use SHA-256 (a form of SHA-2) when generating your certificate.

For more information on generating and installing a certificate, see:

* this author's [guide to setting up HTTPS](https://konklone.com/post/switch-to-https-now-for-free#generating-the-certificate)
* this author's [nginx configuration](https://gist.github.com/konklone/6532544) that produces [this SSL Labs rating](https://www.ssllabs.com/ssltest/analyze.html?d=konklone.com)

## Author

This is a tiny tool by [Eric Mill](https://twitter.com/konklone). Released under an [MIT License](LICENSE).
