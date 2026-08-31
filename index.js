const lief = require('bare-lief')

// Eject the embedded Bare bundle from a standalone binary and return its raw
// bytes. `binary` is the whole executable as a Buffer/Uint8Array.
//
// bare-build embeds the bundle behind a container-specific anchor:
//
//   Mach-O   segment __BARE, section __bundle
//   ELF      region between the __bare_bundle_begin / __bare_bundle_end symbols
//   PE       section .bare
//
// LIEF (via bare-lief) does the container parsing; we just pull the right
// bytes out. Returns null when the binary carries no embedded bundle.
module.exports = exports = function eject(binary) {
  if (!ArrayBuffer.isView(binary) || binary.byteLength < 4) return null

  const buffer = Buffer.isBuffer(binary) ? binary : Buffer.from(binary)

  const magic = ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) >>> 0

  try {
    if (magic === 0x7f454c46) return fromELF(buffer)
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) return fromPE(buffer)
    if (MACHO_MAGICS.has(magic)) return fromMachO(buffer)
  } catch {
    return null
  }

  return null
}

// Thin (32/64-bit, both byte orders) and fat Mach-O magics.
const MACHO_MAGICS = new Set([
  0xfeedface,
  0xfeedfacf,
  0xcefaedfe,
  0xcffaedfe, // thin
  0xcafebabe,
  0xcafebabf,
  0xbebafeca,
  0xbfbafeca // fat
])

function fromMachO(buffer) {
  const fat = lief.MachO.FatBinary.parse(buffer)

  for (let i = 0; i < fat.size; i++) {
    const section = fat.at(i).getSection('__bundle')
    if (section) return section.content
  }

  return null
}

function fromELF(buffer) {
  const elf = lief.ELF.Binary.parse(buffer)

  const begin = symbolValue(elf, '__bare_bundle_begin')
  const end = symbolValue(elf, '__bare_bundle_end')
  if (begin === null || end === null || end < begin) return null

  const offset = elf.virtualAddressToOffset(begin)
  if (offset < 0) return null

  return buffer.subarray(offset, offset + (end - begin))
}

function symbolValue(elf, name) {
  const symbol = elf.getDynamicSymbol(name) || elf.getSymtabSymbol(name)
  return symbol ? symbol.value : null
}

function fromPE(buffer) {
  const pe = lief.PE.Binary.parse(buffer)

  const section = pe.getSection('.bare')
  return section ? section.content : null
}
