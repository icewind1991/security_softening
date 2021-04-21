# ⚠ DON'T USE THIS ⚠

This app completely breaks protection against password bruteforcing and other security hardening, don't use it.

### If I'm not allowed to use this, then why does it exist?

Because the time spend checking password adds noise to benchmarking, and CSRF checks are annoying when trying to test and api endpoint.

### After I've ignored all warnings and installed it anyway, how do I use it?

The password bruteforce protection bypass is enabled automatically, the CSRF bypass is enabled by setting a non-empty `CSRF` header.
