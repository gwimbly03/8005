set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <password>" >&2
  exit 1
fi
PW="$1"

have(){ command -v "$1" >/dev/null 2>&1; }

echo "Tools:"
have mkpasswd && echo "  mkpasswd: $(command -v mkpasswd)"
have htpasswd && echo "  htpasswd: $(command -v htpasswd)"
have openssl  && echo "  openssl:  $(command -v openssl)"
echo

# yescrypt (mkpasswd must be built with yescrypt)
if have mkpasswd && mkpasswd -m help 2>/dev/null | grep -q '\byescrypt\b'; then
  echo "yescrypt:"
  mkpasswd -m yescrypt "$PW"
else
  echo "yescrypt: unsupported by your mkpasswd build"
fi
echo

# scrypt (mkpasswd must be built with scrypt)
if have mkpasswd && mkpasswd -m help 2>/dev/null | grep -q '\bscrypt\b'; then
  echo "scrypt:"
  mkpasswd -m scrypt "$PW"
else
  echo "scrypt: unsupported by your mkpasswd build"
fi
echo

# bcrypt: prefer htpasswd; fall back to mkpasswd if it supports bcrypt
if have htpasswd; then
  echo "bcrypt (htpasswd, cost 12):"
  htpasswd -nbBC 12 user "$PW" | cut -d: -f2
elif have mkpasswd && mkpasswd -m help 2>/dev/null | grep -q '\bbcrypt\b'; then
  echo "bcrypt (mkpasswd, cost 12):"
  mkpasswd -m bcrypt -R 12 "$PW"
else
  echo "bcrypt: no supporting tool found"
fi
echo

# SHA-512-crypt via OpenSSL (random salt if none given)
if have openssl; then
  echo "sha-512-crypt:"
  openssl passwd -6 "$PW"
else
  echo "sha-512-crypt: openssl not found"
fi
echo

# SHA-256-crypt via OpenSSL if supported
if have openssl && openssl passwd -5 test >/dev/null 2>&1; then
  echo "sha-256-crypt:"
  openssl passwd -5 "$PW"
else
  echo "sha-256-crypt: unsupported by your OpenSSL build"
fi
echo

# MD5-crypt (Apache variant) via OpenSSL
if have openssl; then
  echo "md5-crypt (apr1):"
  openssl passwd -apr1 "$PW"
else
  echo "md5-crypt: openssl not found"
fi
