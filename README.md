# totp-enroll

Let a user register their own TOTP seed on a host where the seeds are kept in a
directory only root can write.

A daemon behind a unix socket does the writing. The kernel names the peer, so a
caller can only ever enrol themselves.

Nothing is written until the caller sends back a code from the seed, so a seed
the authenticator app never received is never saved.

## Usage

Run the daemon as root.

```
totp-enroll -daemon -issuer gw.example.com -seed-dir /etc/google-authenticator
```

The caller runs it with no arguments.

```
$ totp-enroll

  <QR code>

Scan the code, or enter the address by hand:

  otpauth://totp/gw.example.com:alice?secret=...&issuer=gw.example.com

Code from the app: 123456

Enrolled. The next login will ask for a code.
```

A user who already holds a seed is refused. Remove the file to let them enrol
again.

The seed is written in the layout `pam_google_authenticator` reads. `-seed-dir`
has to name the directory pam is reading, or the enrolment will look like it
worked and the login will still be refused.

## As a service

A unit file is in `systemd/`. Fill in `-issuer` and `-seed-dir` in `ExecStart`,
then

```
cp systemd/totp-enroll.service /etc/systemd/system/
systemctl enable --now totp-enroll
```

## Requires

`qrencode`. Without it the address is still offered, only the picture is
missing.

## License

This project is licensed under the [MIT License](LICENSE).
