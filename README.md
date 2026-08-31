# bare-standalone-bundle-extract

Eject the [Bare](https://github.com/holepunchto/bare) bundle embedded in a standalone binary built with [`bare-build`](https://github.com/holepunchto/bare-build).

When `bare-build` produces a standalone executable, it embeds the application bundle into the binary using a platform-specific anchor:

| Platform        | Container | Anchor                                              |
| --------------- | --------- | --------------------------------------------------- |
| macOS / iOS     | Mach-O    | segment `__BARE`, section `__bundle`                |
| Linux / Android | ELF       | symbols `__bare_bundle_begin` / `__bare_bundle_end` |
| Windows         | PE        | section `.bare`                                     |

`bare-standalone-bundle-extract` reads any such binary as raw bytes and hands back the embedded bundle. Container parsing is handled by [LIEF](https://lief.re) (via [`bare-lief`](https://github.com/holepunchto/bare-lief)), so a build running on any host can inspect a binary for any target.

```
npm i bare-standalone-bundle-extract
```

## Usage

```js
const fs = require('bare-fs')
const Bundle = require('bare-bundle')
const extract = require('bare-standalone-bundle-extract')

const binary = fs.readFileSync('./my-standalone-app')

const bytes = extract(binary)

if (bytes === null) {
  console.log('no embedded bundle found')
} else {
  const bundle = Bundle.from(bytes)
  console.log('main entrypoint:', bundle.main)
}
```

## API

#### `const bytes = extract(binary)`

Locate the embedded Bare bundle within `binary` and return its raw bytes. `binary` is the whole executable as a `Buffer` or `Uint8Array`.

Returns a `Buffer`; pass it straight to `require('bare-bundle').from(...)`.

Returns `null` when the binary carries no embedded bundle.

## License

Apache-2.0
