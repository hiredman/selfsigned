# selfsigned

A Clojure library designed to generate a self signed cert in a
keystore in memory

## Usage

`[com.manigfeald/selfsigned "0.1.0"]`

``` clojure
(require '[com.manigfeald.selfsigned :refer [self-signed-keystore]])

(self-signed-keystore "foo")
```

self-signed-keystore returns a keystore that contains a single entry
protected by the password you give it. the password is also used as
the certificate's common name.

## License

Copyright © 2014 Kevin Downey

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
