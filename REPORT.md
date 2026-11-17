# Lab 4 report

Built on 17 November 2026, with OpenSSL 3.5.9 in the lab containers. Numbers below come from the
files in this repository. The three runs of `check.sh` are in `evidence/`: `working.txt` (27 passed),
`broken.txt` (33 passed) and `fixed.txt` (34 passed).

## 1. Inventory

| Item | Key location | Readable by | Valid until | Purpose |
|---|---|---|---|---|
| Root CA, EC P-384, self-signed, serial `1684CBA8…D8A2`, `root/certs/ca.cert.pem` | `root/private/ca.key.pem`, encrypted with AES-256 and a passphrase, folder mode 700 | the `root-ca` container only, and root on the host. No network in that container. The passphrase is in my head for the lab; a real team would keep it in a vault | 2046-11-12, 20 years | signs the intermediate and the root CRL. Stopped after phase 2 |
| Issuing CA, EC P-384, serial `1000`, `intermediate/certs/int.cert.pem` | `intermediate/private/int.key.pem`, mode 600, not encrypted | the `issuing-ca` container only. No network. Root on the host | 2036-11-14, 10 years | signs every server and client certificate, and the intermediate CRL |
| Server `www.lab.internal`, EC P-256, serial `1000`, `identities/www/www.cert.pem` | `identities/www/www.key.pem`, mode 600. An age copy `www.key.pem.age` goes to git | the `client` container, nginx as root, and me on the host | 2027-02-15, 90 days | TLS server on port 443 of nginx |
| alice, EC P-256, serial `1005`, `identities/alice/alice.cert.pem` | `identities/alice/alice.key.pem`, mode 600, plus `alice.key.pem.age` in git | the `client` container and me | 2027-02-15, 90 days | admin client certificate: `/admin` |
| alice, old certificate, serial `1002`, revoked 2026-11-17 10:18:52 UTC with `keyCompromise` | the stolen key, replaced in phase 6 | nobody should read it any more | 2027-02-15, but refused by the CRL | was admin, now listed in `intermediate/crl/int.crl.pem` |
| bob, EC P-256, serial `1003`, `identities/bob/bob.cert.pem` | `identities/bob/bob.key.pem` and its `.age` | the `client` container and me | 2027-02-15, 90 days | user client certificate: `/whoami` only |
| billing, EC P-256, serial `1004`, `identities/billing/billing.cert.pem` | `identities/billing/billing.key.pem` and its `.age` | the `client` container and me | 2027-02-15, 90 days | service certificate: `/invoices`, SAN `URI:spiffe://lab.internal/billing` |
| `evil.example.com`, EC P-256, serial `1001`, `exchange/evil.cert.pem` | `identities/evil/evil.key.pem` and its `.age` | the `client` container and me | 2027-02-15, 90 days | test only. Signed, but never valid, see section 2 |

The keys in `identities/` also exist as `.age` files, encrypted to the three keys in `recipients.txt`:
mine, the CI's and the trainer's. The CA keys are not in git at all, clear or encrypted.

**Lifetimes.** The root lasts 20 years because it is offline, rarely signed, and lives in trust stores
that are painful to update. A shorter life would mean a full trust store change more often. A longer
life is possible but it only increases the time an eventual leak stays dangerous. The intermediate
lasts 10 years so the root can stay offline for a decade; every leaf reissue does not need the root.
Leaves last 90 days. One year gives a thief too much time with a working certificate. Seven days
would mean reissuing constantly, by hand in this lab, and the CRL already lives 7 days. 90 days is
short enough to limit damage and long enough to be workable. `check.sh` refuses anything above 90 days.

## 2. Chain

Every line comes from `openssl x509 -noout -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName`.

| Certificate | Subject, issuer | Constraining extensions | What they prevent |
|---|---|---|---|
| root | `C=FR, O=EPITA Lab, CN=EPITA Lab Root CA`, self-signed | `CA:TRUE, pathlen:1`; `keyUsage: certSign, cRLSign, digitalSignature` | `pathlen:1`: one CA level below the root, no more. The root key signs certificates and CRLs, not TLS sessions |
| intermediate | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, issued by the root | `CA:TRUE, pathlen:0`; `keyUsage: certSign, cRLSign`; `nameConstraints: permitted DNS:lab.internal` | `pathlen:0`: it cannot create another CA. `nameConstraints`: it cannot certify a name outside `lab.internal` |
| www | `CN=www.lab.internal`, issued by the intermediate | `CA:FALSE`; `keyUsage: digitalSignature`; `EKU: serverAuth`; `SAN: DNS:www.lab.internal` | it cannot act as a client certificate, and it is bound to one name |
| alice, bob | `CN=alice`, `CN=bob`, issued by the intermediate | `CA:FALSE`; `EKU: clientAuth`; `SAN: email:…@lab.internal` | they cannot act as a server. Their email is in the SAN, the API still reads the CN |
| billing | `CN=billing`, issued by the intermediate | `CA:FALSE`; `EKU: clientAuth`; `SAN: URI:spiffe://lab.internal/billing` | a person certificate cannot pretend to be the service, and the other way round, once a policy checks the SAN |
| evil.example.com | `CN=evil.example.com`, issued by the intermediate | same as www, `SAN: DNS:evil.example.com` | nothing at signing time. Validation refuses it |

The last line is the point of `nameConstraints`. The intermediate did sign `evil.example.com` in phase 3,
but any client that validates the chain refuses it:

```text
$ openssl verify -CAfile root/certs/ca.cert.pem -untrusted intermediate/certs/int.cert.pem exchange/evil.cert.pem
error 47 at 0 depth lookup: permitted subtree violation
```

The chain as nginx sends it is `identities/www/www.fullchain.pem`, leaf first, then the intermediate.
`openssl s_client` shows `0 s:CN=www.lab.internal`, `1 s:C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`
and `Verify return code: 0 (ok)` when `root/certs/ca.cert.pem` is the trust anchor.

## 3. Key compromise

### Server key (`identities/www/www.key.pem`)

- How I notice: nothing in this build watches it. There is no alert, no log check, no monitoring. I
  learn it from outside: a leak, a stolen backup, or someone with access to the host.
- What becomes unsafe: whoever has the key can run a fake `www.lab.internal` if they can also redirect
  the name (DNS or the same network). Clients then send their requests to the attacker. It cannot reach
  the API as alice, that needs a client key. Past sessions stay private, because TLS 1.3 uses ephemeral
  ECDHE keys, so the server key alone does not decrypt them. Nothing stops working.
- Recovery: new P-256 key and CSR in `client`, sign it in `issuing-ca`, copy it to `identities/www/`,
  copy the new full chain, then `docker compose restart nginx`. Revoke the old serial and publish the
  CRL. But `curl` and browsers do not fetch a CRL for the server, so the old certificate is still
  accepted by clients until it expires.
- How long: about 10 minutes to reissue and restart. The stolen certificate stays usable until
  2027-02-15, up to 90 days, unless every client checks OCSP or CRL, which this lab does not.

### Client key (alice)

- How I notice: late. This exact case is phase 5: I only knew because the lab told me the laptop was
  stolen. `intermediate/index.txt` and the CRL show a revocation only after I run it. The API logs
  (`api/app.py` prints one line per request) could show unusual calls from alice, but only after the
  fact, and only if someone reads them.
- What becomes unsafe: the holder of the key and certificate is alice. `curl` with `CN=alice` gets
  `{"user": "alice", "role": "admin", "path": "/admin"}` with status 200. So the attacker reads and
  changes whatever alice can. bob's key cannot do this: bob gets 403 on `/admin`, as shown in
  `evidence/working.txt`.
- Recovery: done in phases 5 and 6. Revoke serial `1002` with reason `keyCompromise`
  (`openssl ca -revoke … -crl_reason keyCompromise`), regenerate the intermediate CRL, rebuild
  `intermediate/crl/crl-bundle.pem` with both CRLs, restart nginx. Then a new key and a new CSR for
  alice, signed as serial `1005`, copied to `identities/alice/`. The old key stays stolen, but its
  certificate is now refused at every chain level.
- How long: minutes for the revocation, the CRL and the restart. The new certificate takes minutes
  more. The real cost is finding out, which this build cannot do.

### Intermediate key

- How I notice: with difficulty. It signs a valid chain, so every check still passes. Nothing in the
  lab logs signatures. No certificate transparency applies to a private CA. I would find out from a
  forged certificate in use, or not at all.
- What becomes unsafe: everything under `lab.internal`. The attacker can issue a client certificate
  with `CN=alice` and `EKU clientAuth` and pass nginx, because the API trusts the CN in
  `X-Client-DN`. They can also issue a server certificate for `www.lab.internal`. `pathlen:0` stops a
  new CA below it, not this. The damage lasts until 2036 if nobody notices.
- Recovery: the root has to revoke the intermediate and publish a new root CRL. The root is offline,
  so the passphrase holder must be available. A new intermediate key and certificate are needed, then
  a new `ca-chain.pem` for nginx, a new `ssl_client_certificate` file, and every leaf certificate
  must be reissued, because all of them chain to the revoked intermediate. The root CRL has to reach
  every validator too.
- How long: hours to days. It needs the root key holder, a new intermediate, all servers and clients
  reissued, and all CRL files replaced and deployed.

### Root key

- How I notice: only by accident, or when someone shows a forged chain. The key is offline, so there
  is no log to watch and no traffic that touches it.
- What becomes unsafe: the whole PKI. The attacker can create a new intermediate and any certificate
  below it. A fake root with the same name does not work against clients that already trust the real
  root certificate, because trust is by key, not by name. But the real root key gives the same power.
  There is no authority above it to say the key is bad.
- Recovery: build a new root, a new intermediate and all leaves again, then install the new root on
  every laptop, server and container and remove the old one. There is no revocation that reaches
  clients: browsers and operating systems do not fetch a root CRL. A company would plan a cross-signed
  transition, but here there is no second root.
- How long: days to weeks, since every device needs a manual trust store change. In this lab, one
  laptop and a few containers, so hours. That is not the realistic case.

## 4. Operational gaps

- **Root passphrase.** In this lab the passphrase is only in my head. That is fine for one person for
  one day, and bad for a team. If I am sick or I leave, nobody can sign a CRL or a new intermediate,
  and the PKI is stuck. A real setup keeps it in a vault or a password manager with an owner and a
  backup, or splits it with Shamir shares, for example 2 of 3 people. The key itself belongs in an
  HSM, and the procedure for a new holder must be written before it is needed.
- **CRL expiry.** `default_crl_days = 7` in `intermediate/openssl.cnf`. The current CRL expires on
  2026-11-24 10:19 UTC (`openssl crl -noout -nextupdate`). On day 8, nginx refuses every client,
  bob and billing included, with a CRL expired error, so the whole API is down, not just alice. The
  root CRL lives 180 days, so it is less urgent but still expires. Someone must run
  `openssl ca -gencrl` on `issuing-ca` at least every 6 days, rebuild `crl-bundle.pem`, and restart
  nginx. In this lab that is me, by hand. In a company it is a scheduled job with an alert before
  `nextUpdate`, and a named on-call person.
- **Root in trust stores.** `root/certs/ca.cert.pem` is trusted by nobody outside this machine. Each
  laptop would need it in the system store (`/usr/local/share/ca-certificates/` plus
  `update-ca-certificates` on Debian, `update-ca-trust` on RHEL, keychain on macOS and Windows), and
  each container image would need it copied in at build time. Java has its own `cacerts`, and Python
  uses `certifi`, so both need the file too. Tools like Ansible, Puppet or an MDM push it. Removal
  matters as much as install: when the root changes, the old one must leave every store.
- **Intermediate key not encrypted.** The file is mode 600 and owned by root, so only the container
  can read it, but it is still a plain file on the host disk. A KMS or HSM fixes that: the key is
  created inside the device, never exported, and `openssl ca` sends each signature request to it.
  With a real KMS, the machine that signs never holds the key, and
  access is controlled by IAM or a PIN and logged. The price is per signature latency, a vendor
  dependency, and the loss of plain offline `openssl ca` with a file key. That is the normal trade
  for an issuing CA in production.
