# ti-verify

`ti-verify` checks the Texas Inference API gateway before you send it anything. It asks the gateway for an Intel TDX quote bound to the TLS connection it opened, checks Intel's signature on the quote, and compares what the confidential VM measured at boot with the release record Texas Inference published for that gateway.

What a PASS means, and what it does not:

- The gateway answering at that address is an Intel TDX confidential VM whose boot measurements equal our release record, on hardware whose security version Intel currently accepts.
- The release record is Texas Inference's own statement of what the gateway image measures. The image's source is not public yet, so you are trusting us for what that image does.
- It checks the connection `ti-verify` itself opened. It prints the gateway's key hash: pin it in your own client if you want your API calls bound to the same key.
- It checks the gateway VM only, not the GPU worker behind it, and it does not cover physical attacks on the hardware.

## 1. Download

From the release page of this repository, download the file for your machine:

- `ti-verify-x86_64-unknown-linux-musl` (Linux x86_64)
- `ti-verify-aarch64-unknown-linux-musl` (Linux arm64)
- `ti-verify-aarch64-apple-darwin` (macOS on Apple silicon)

and `SHA256SUMS`, `SHA256SUMS.sig`, `allowed_signers` and `release.json`.

## 2. Check that the files are ours

Check a release with our release keys as the Texas Inference website publishes them, not with the `allowed_signers` file in the download. Listing the fingerprints of that file is not enough: the listing skips lines it cannot parse without a warning, so a doctored `allowed_signers` can hide an extra key that `ssh-keygen -Y verify` still accepts.

Copy the two key lines from https://texasinference.ai/proof#release-keys into a file named `texas-inference-keys` in the folder with the release files. Keep that file for later releases. Then:

```
ssh-keygen -Y verify -f texas-inference-keys -I release@texasinference.ai -n ti-verify-release -s SHA256SUMS.sig < SHA256SUMS
```

The output must start with `Good "ti-verify-release" signature for release@texasinference.ai`. Then check your files against the signed sums:

```
sha256sum -c SHA256SUMS --ignore-missing        # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing    # macOS
```

## 3. Verify the gateway

The current release records are in `records/releases.json` in this repository. They are renewed at least every 31 days.

```
chmod +x ti-verify-<target>
xattr -d com.apple.quarantine ti-verify-aarch64-apple-darwin    # macOS, after a browser download
./ti-verify-<target> https://api.texasinference.ai --release records/releases.json
```

It prints one line, `PASS: ...` or `FAIL: <reason> (<detail>)`, and exits 0 or 1. Send nothing if it does not print PASS. It needs to reach Intel's certification service to fetch collateral.

## 4. Rebuild it yourself (optional)

The Linux binaries are reproducible in the reference environment: an Ubuntu 24.04 container with packages from the Ubuntu snapshot archive at a fixed time. The release's `build-<target>.txt` names the image digest, the snapshot time and every compiler version we used. At the release tag of this repository, with Docker installed, run the script. It uses the image digest pinned in `build-in-docker.sh`, which must equal the `image:` line of the release's build note:

```
./build-in-docker.sh x86_64-unknown-linux-musl     # on an x86_64 machine
./build-in-docker.sh aarch64-unknown-linux-musl    # on an arm64 machine
```

Each prints the SHA-256 of your build. When your `build-<target>.txt` equals the release's, the hash must equal the line for that target in `SHA256SUMS`. A build outside the container usually differs, because the Linux binary contains C code compiled by your machine's compiler.

The macOS binary also depends on the Xcode version in `build-aarch64-apple-darwin.txt`. `./reproduce.sh aarch64-apple-darwin` matches only with that Xcode.
