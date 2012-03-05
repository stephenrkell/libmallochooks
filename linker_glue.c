/* If we're using the preload or wrap methods, we have to convert 
 * the signature of malloc (et al) calls into that expected by the
 * hooks. In particular, the hooks have an extra "caller" argument
 * that we source from the return address. */
