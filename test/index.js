const test = require('brittle')
const fs = require('bare-fs')
const path = require('bare-path')
const Bundle = require('bare-bundle')
const eject = require('..')

// One standalone binary per target. A real bare-build standalone is 40-130 MB,
// nearly all of it Bare runtime, so these are minimal containers carrying the
// same small bundle behind the same anchor bare-build uses; see
// fixtures/generate.js, which regenerates them via `npm run fixtures`. Because
// the payload is shared, the recovered bundle is identical regardless of the
// container format (Mach-O / ELF / PE) it was extracted from.
const files = ['/index.js', '/lib/greet.js', '/package.json']
const targets = [
  { name: 'darwin-arm64', format: 'Mach-O', binary: 'pear' },
  { name: 'darwin-x64', format: 'Mach-O', binary: 'pear' },
  { name: 'linux-arm64', format: 'ELF', binary: 'pear' },
  { name: 'linux-x64', format: 'ELF', binary: 'pear' },
  { name: 'win32-arm64', format: 'PE', binary: 'pear.exe' },
  { name: 'win32-x64', format: 'PE', binary: 'pear.exe' }
]

function read(target) {
  return fs.readFileSync(
    path.join(__dirname, 'fixtures', 'by-arch', target.name, 'app', target.binary)
  )
}

// Guards against a target being added to the tree but never exercised: a
// missing binary already fails loudly in read(), an unlisted one would not.
test('every target with a standalone binary is exercised', (t) => {
  const available = fs.readdirSync(path.join(__dirname, 'fixtures', 'by-arch')).sort()

  t.alike(available, targets.map((target) => target.name).sort(), 'no target goes untested')
})

for (const target of targets) {
  test(`extracts a decodable bundle from a ${target.format} standalone (${target.name})`, (t) => {
    const binary = read(target)
    const bytes = eject(binary)

    t.ok(bytes, 'located an embedded bundle')
    if (bytes === null) return

    const bundle = Bundle.from(bytes)
    t.ok(bundle.exists(bundle.main), 'main file present in bundle')
    t.alike([...bundle.keys()].sort(), files, 'every file recovered')
  })
}

test('returns null for a buffer that is not a bare-build binary', (t) => {
  t.is(eject(Buffer.from('not an executable at all')), null)
})

test('returns null for an empty buffer', (t) => {
  t.is(eject(Buffer.alloc(0)), null)
})
