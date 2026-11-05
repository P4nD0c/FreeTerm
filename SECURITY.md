# Security policy

FreeTerm handles SSH passwords and private keys, so security reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab → "Report a vulnerability"). You should get an answer
within a few days.

## How FreeTerm protects your data

- **Saved data is encrypted.** Hosts, passwords, keys and settings are stored in
  `%APPDATA%\FreeTerm\workspace.dat`, encrypted with Windows DPAPI for your Windows
  user account. Another user on the same PC, or someone who copies the file to another
  machine, cannot read it. Anyone who can log in as *you* can.
- **Private keys live on disk only briefly.** To hand a key to OpenSSH, FreeTerm writes
  it to `%APPDATA%\FreeTerm\keys\` and deletes it 5 minutes after the last connection
  that used it, and again when the app starts and exits.
- **Server identity is checked.** SSH terminals use OpenSSH, which shows the server's
  fingerprint and asks before trusting a new server. SFTP only connects to servers that
  are already trusted (in FreeTerm's own `known_hosts`) and refuses SSH certificates.
- **Saved passwords are typed only at the login prompt.** A saved password or key
  passphrase is sent only when the line under the cursor is an OpenSSH login prompt,
  and only during the first 90 seconds of a session.
- **No telemetry.** FreeTerm makes no network connections other than the ones you open.

## Known limitations

- When generating a key with a passphrase, the passphrase is passed to `ssh-keygen.exe`
  on its command line, so other programs running as your user could see it for the
  moment the process runs.
- Typed commands (shell history) and session logs are kept in the encrypted workspace.
  They can be cleared from the app.
