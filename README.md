# XPI Sign GitHub Action

Sign an existing Firefox XPI with a user-managed X.509 certificate authority.
The action generates a new leaf certificate for the add-on ID, signs the XPI
using Mozilla-compatible JAR/CMS/PKCS#7 metadata, and exposes the signed file
path as `steps.<id>.outputs.target`.

Requires a Linux runner with Node.js, OpenSSL, `zip`, and `unzip` (available on
GitHub-hosted Ubuntu runners). The action does not upload to AMO or change a
GitHub Release.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `source` | Yes | — | Existing unsigned `.xpi` path (same purpose as `action-web-ext`'s `source`) |
| `artifacts` | No | `signed` | Directory for the signed XPI |
| `privateKey` | Yes | — | Signing CA private key, PEM text or file path |
| `certificate` | Yes | — | Signing CA public certificate, PEM text or file path |
| `expectedId` | No | — | Refuse to sign if the XPI add-on ID differs |

## Outputs

| Output | Description |
| --- | --- |
| `target` | Absolute path to the signed XPI |

The signed XPI keeps the original basename inside `artifacts/`. Signing an XPI
replaces its existing `META-INF` signature metadata. The original source file
is not modified.

## Example: WebHID

The public certificate is distributed separately through
`OpenPolyfill/xpi-manifest`. After publishing and tagging this action:

```yaml
- uses: actions/checkout@v4
  with:
    repository: OpenPolyfill/xpi-manifest
    path: xpi-manifest

- name: Sign XPI with OpenPolyfill CA
  id: ea-sign
  uses: OpenPolyfill/action-xpi-sign@v1
  with:
    source: dist/webhid-addon-v${{ steps.variables.outputs.VERSION }}.xpi
    artifacts: signed
    privateKey: ${{ secrets.XPI_CA_PRIVATE_KEY_PEM }}
    certificate: xpi-manifest/certificates/openpolyfill-ca.pem
    expectedId: webhid@k4zoku.dev

- name: Inspect signed output
  run: file "${{ steps.ea-sign.outputs.target }}"
```

The caller supplies its own CA. Keep `privateKey` in GitHub Actions Secrets;
it is written only to a temporary file on the signing runner and removed when
the action ends. `certificate` may point to a public file in a checked-out repo.

The signature structure and certificate restrictions follow the same signing
logic as Sine Experiment Bridge 0.8.2 and Experiments Authority. The signer
requires an explicit Gecko add-on ID in `manifest.json`.

## License

GPL-3.0-or-later.
