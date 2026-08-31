// Regenerate the standalone fixtures under `by-arch`:
//
//   npm run fixtures
//
// A real bare-build standalone is 40-130 MB, nearly all of it Bare runtime, so
// the fixtures are hand-built instead: the smallest container each target's
// loader format allows, carrying the same small bundle behind the same anchor
// bare-build uses. That keeps what the extractor actually reads -- Mach-O
// segment/section names, ELF dynamic symbols, PE section names -- faithful to
// real output while keeping the tree checkout-sized.

const fs = require('bare-fs')
const path = require('bare-path')
const Bundle = require('bare-bundle')

const targets = [
  { name: 'darwin-arm64', binary: 'pear', write: machO, arch: 'arm64' },
  { name: 'darwin-x64', binary: 'pear', write: machO, arch: 'x64' },
  { name: 'linux-arm64', binary: 'pear', write: elf, arch: 'arm64' },
  { name: 'linux-x64', binary: 'pear', write: elf, arch: 'x64' },
  { name: 'win32-arm64', binary: 'pear.exe', write: pe, arch: 'arm64' },
  { name: 'win32-x64', binary: 'pear.exe', write: pe, arch: 'x64' }
]

// The application every fixture carries. Kept deliberately small; the extractor
// cares about the container, not the payload.
function app() {
  return new Bundle()
    .write('/package.json', JSON.stringify({ name: 'pear', main: 'index.js' }, null, 2) + '\n')
    .write('/index.js', "const greet = require('./lib/greet')\n\ngreet('world')\n", {
      main: true
    })
    .write('/lib/greet.js', 'module.exports = function greet(name) {\n  console.log(name)\n}\n')
    .toBuffer()
}

function align(value, to) {
  return Math.ceil(value / to) * to
}

// Mach-O: segment __BARE, section __bundle.

const MH_MAGIC_64 = 0xfeedfacf
const MH_EXECUTE = 0x2
const LC_SEGMENT_64 = 0x19

const CPU_TYPE = { arm64: 0x0100000c, x64: 0x01000007 }
const CPU_SUBTYPE = { arm64: 0x00000000, x64: 0x00000003 }

function machO(bundle, arch) {
  const pageSize = 0x4000

  const commands = 72 + (72 + 80) // __TEXT, then __BARE with one section
  const offset = pageSize

  const file = Buffer.alloc(offset + bundle.byteLength)

  file.writeUInt32LE(MH_MAGIC_64, 0)
  file.writeInt32LE(CPU_TYPE[arch], 4)
  file.writeInt32LE(CPU_SUBTYPE[arch], 8)
  file.writeUInt32LE(MH_EXECUTE, 12)
  file.writeUInt32LE(2, 16) // ncmds
  file.writeUInt32LE(commands, 20)
  file.writeUInt32LE(0x00200001, 24) // MH_NOUNDEFS | MH_PIE
  file.writeUInt32LE(0, 28)

  const base = 0x100000000

  segmentCommand(file, 32, {
    name: '__TEXT',
    address: base,
    memorySize: pageSize,
    offset: 0,
    size: pageSize,
    protection: 0x5, // read | execute
    sections: 0
  })

  segmentCommand(file, 32 + 72, {
    name: '__BARE',
    address: base + pageSize,
    memorySize: align(bundle.byteLength, pageSize),
    offset,
    size: bundle.byteLength,
    protection: 0x1, // read
    sections: 1
  })

  section(file, 32 + 72 + 72, {
    name: '__bundle',
    segment: '__BARE',
    address: base + pageSize,
    size: bundle.byteLength,
    offset
  })

  bundle.copy(file, offset)

  return file
}

function segmentCommand(file, at, opts) {
  const { name, address, memorySize, offset, size, protection, sections } = opts

  file.writeUInt32LE(LC_SEGMENT_64, at)
  file.writeUInt32LE(72 + 80 * sections, at + 4)
  file.write(name, at + 8, 16, 'ascii')
  file.writeBigUInt64LE(BigInt(address), at + 24)
  file.writeBigUInt64LE(BigInt(memorySize), at + 32)
  file.writeBigUInt64LE(BigInt(offset), at + 40)
  file.writeBigUInt64LE(BigInt(size), at + 48)
  file.writeInt32LE(protection, at + 56) // maxprot
  file.writeInt32LE(protection, at + 60) // initprot
  file.writeUInt32LE(sections, at + 64)
  file.writeUInt32LE(0, at + 68) // flags
}

function section(file, at, opts) {
  const { name, segment, address, size, offset } = opts

  file.write(name, at, 16, 'ascii')
  file.write(segment, at + 16, 16, 'ascii')
  file.writeBigUInt64LE(BigInt(address), at + 32)
  file.writeBigUInt64LE(BigInt(size), at + 40)
  file.writeUInt32LE(offset, at + 48)
  file.writeUInt32LE(0, at + 52) // align, 2^0
  // reloff, nreloc, flags and the three reserved fields all stay zero
}

// ELF: the bundle is mapped by its own load segment and delimited by the weak
// dynamic symbols __bare_bundle_begin / __bare_bundle_end.

const ET_DYN = 3

const EM = { arm64: 183, x64: 62 }

const SHT_PROGBITS = 1
const SHT_STRTAB = 3
const SHT_DYNAMIC = 6
const SHT_DYNSYM = 11

const SHF_WRITE = 0x1
const SHF_ALLOC = 0x2

const PT_LOAD = 1
const PT_DYNAMIC = 2

const PF_R = 0x4
const PF_W = 0x2

const DT_NULL = 0
const DT_STRTAB = 5
const DT_SYMTAB = 6
const DT_STRSZ = 10
const DT_SYMENT = 11

const STB_WEAK = 2

function elf(bundle, arch) {
  const pageSize = 0x1000

  const symbols = ['__bare_bundle_begin', '__bare_bundle_end']
  const sectionNames = ['', '.dynsym', '.dynstr', '.dynamic', '.bare', '.shstrtab']

  const dynstr = strtab(symbols)
  const shstrtab = strtab(sectionNames)

  // Everything but the bundle and the section headers lives in the first page,
  // identity mapped so that a virtual address is also a file offset.
  const phoff = 64
  const phnum = 3

  const dynsymOffset = align(phoff + phnum * 56, 8)
  const dynsymSize = (symbols.length + 1) * 24
  const dynstrOffset = dynsymOffset + dynsymSize
  const dynamicOffset = align(dynstrOffset + dynstr.buffer.byteLength, 8)
  const dynamicSize = 5 * 16
  const shstrtabOffset = dynamicOffset + dynamicSize

  const bundleOffset = pageSize
  const shoff = align(bundleOffset + bundle.byteLength, 8)
  const shnum = sectionNames.length

  const file = Buffer.alloc(shoff + shnum * 64)

  file.write('\x7fELF\x02\x01\x01', 0, 'binary') // 64-bit, little-endian
  file.writeUInt16LE(ET_DYN, 16)
  file.writeUInt16LE(EM[arch], 18)
  file.writeUInt32LE(1, 20) // e_version
  file.writeBigUInt64LE(BigInt(phoff), 32)
  file.writeBigUInt64LE(BigInt(shoff), 40)
  file.writeUInt16LE(64, 52) // e_ehsize
  file.writeUInt16LE(56, 54) // e_phentsize
  file.writeUInt16LE(phnum, 56)
  file.writeUInt16LE(64, 58) // e_shentsize
  file.writeUInt16LE(shnum, 60)
  file.writeUInt16LE(sectionNames.indexOf('.shstrtab'), 62)

  programHeader(file, phoff, {
    type: PT_LOAD,
    flags: PF_R,
    offset: 0,
    address: 0,
    size: pageSize,
    alignment: pageSize
  })

  programHeader(file, phoff + 56, {
    type: PT_LOAD,
    flags: PF_R,
    offset: bundleOffset,
    address: bundleOffset,
    size: bundle.byteLength,
    alignment: pageSize
  })

  programHeader(file, phoff + 112, {
    type: PT_DYNAMIC,
    flags: PF_R | PF_W,
    offset: dynamicOffset,
    address: dynamicOffset,
    size: dynamicSize,
    alignment: 8
  })

  // The null symbol is left zeroed; the two anchors follow it, weak and
  // pointing at either end of the bundle.
  const bare = sectionNames.indexOf('.bare')

  symbol(file, dynsymOffset + 24, {
    name: dynstr.offsets[symbols[0]],
    section: bare,
    value: bundleOffset
  })

  symbol(file, dynsymOffset + 48, {
    name: dynstr.offsets[symbols[1]],
    section: bare,
    value: bundleOffset + bundle.byteLength
  })

  dynstr.buffer.copy(file, dynstrOffset)

  dynamic(file, dynamicOffset, [
    [DT_SYMTAB, dynsymOffset],
    [DT_SYMENT, 24],
    [DT_STRTAB, dynstrOffset],
    [DT_STRSZ, dynstr.buffer.byteLength],
    [DT_NULL, 0]
  ])

  shstrtab.buffer.copy(file, shstrtabOffset)

  bundle.copy(file, bundleOffset)

  const sections = [
    {},
    {
      type: SHT_DYNSYM,
      flags: SHF_ALLOC,
      address: dynsymOffset,
      offset: dynsymOffset,
      size: dynsymSize,
      link: sectionNames.indexOf('.dynstr'),
      info: 1, // index of the first non-local symbol
      alignment: 8,
      entrySize: 24
    },
    {
      type: SHT_STRTAB,
      flags: SHF_ALLOC,
      address: dynstrOffset,
      offset: dynstrOffset,
      size: dynstr.buffer.byteLength,
      alignment: 1
    },
    {
      type: SHT_DYNAMIC,
      flags: SHF_ALLOC | SHF_WRITE,
      address: dynamicOffset,
      offset: dynamicOffset,
      size: dynamicSize,
      link: sectionNames.indexOf('.dynstr'),
      alignment: 8,
      entrySize: 16
    },
    {
      type: SHT_PROGBITS,
      flags: SHF_ALLOC,
      address: bundleOffset,
      offset: bundleOffset,
      size: bundle.byteLength,
      alignment: 1
    },
    {
      type: SHT_STRTAB,
      offset: shstrtabOffset,
      size: shstrtab.buffer.byteLength,
      alignment: 1
    }
  ]

  for (let i = 0; i < sections.length; i++) {
    sectionHeader(file, shoff + i * 64, {
      name: shstrtab.offsets[sectionNames[i]],
      ...sections[i]
    })
  }

  return file
}

function strtab(names) {
  const offsets = { '': 0 }

  let offset = 1

  for (const name of names) {
    offsets[name] = offset
    offset += name.length + 1
  }

  return { buffer: Buffer.from('\0' + names.join('\0') + '\0', 'ascii'), offsets }
}

function programHeader(file, at, opts) {
  const { type, flags, offset, address, size, alignment } = opts

  file.writeUInt32LE(type, at)
  file.writeUInt32LE(flags, at + 4)
  file.writeBigUInt64LE(BigInt(offset), at + 8)
  file.writeBigUInt64LE(BigInt(address), at + 16)
  file.writeBigUInt64LE(BigInt(address), at + 24) // p_paddr
  file.writeBigUInt64LE(BigInt(size), at + 32)
  file.writeBigUInt64LE(BigInt(size), at + 40) // p_memsz
  file.writeBigUInt64LE(BigInt(alignment), at + 48)
}

function sectionHeader(file, at, opts) {
  const {
    name = 0,
    type = 0,
    flags = 0,
    address = 0,
    offset = 0,
    size = 0,
    link = 0,
    info = 0,
    alignment = 0,
    entrySize = 0
  } = opts

  file.writeUInt32LE(name, at)
  file.writeUInt32LE(type, at + 4)
  file.writeBigUInt64LE(BigInt(flags), at + 8)
  file.writeBigUInt64LE(BigInt(address), at + 16)
  file.writeBigUInt64LE(BigInt(offset), at + 24)
  file.writeBigUInt64LE(BigInt(size), at + 32)
  file.writeUInt32LE(link, at + 40)
  file.writeUInt32LE(info, at + 44)
  file.writeBigUInt64LE(BigInt(alignment), at + 48)
  file.writeBigUInt64LE(BigInt(entrySize), at + 56)
}

function symbol(file, at, opts) {
  const { name, section, value } = opts

  file.writeUInt32LE(name, at)
  file.writeUInt8(STB_WEAK << 4, at + 4) // weak, no type
  file.writeUInt8(0, at + 5) // st_other
  file.writeUInt16LE(section, at + 6)
  file.writeBigUInt64LE(BigInt(value), at + 8)
  file.writeBigUInt64LE(0n, at + 16) // st_size
}

function dynamic(file, at, entries) {
  for (const [tag, value] of entries) {
    file.writeBigUInt64LE(BigInt(tag), at)
    file.writeBigUInt64LE(BigInt(value), at + 8)
    at += 16
  }
}

// PE: section .bare.

const MACHINE = { arm64: 0xaa64, x64: 0x8664 }

const FILE_ALIGNMENT = 0x200
const SECTION_ALIGNMENT = 0x1000

function pe(bundle, arch) {
  const peOffset = 0x40
  const optionalSize = 240 // PE32+ with all 16 data directories
  const headers = align(peOffset + 4 + 20 + optionalSize + 40, FILE_ALIGNMENT)

  const offset = headers
  const address = SECTION_ALIGNMENT

  const file = Buffer.alloc(offset + align(bundle.byteLength, FILE_ALIGNMENT))

  file.write('MZ', 0, 'ascii')
  file.writeUInt32LE(peOffset, 0x3c) // e_lfanew

  file.write('PE\0\0', peOffset, 'ascii')

  const coff = peOffset + 4

  file.writeUInt16LE(MACHINE[arch], coff)
  file.writeUInt16LE(1, coff + 2) // one section
  file.writeUInt16LE(optionalSize, coff + 16)
  file.writeUInt16LE(0x0022, coff + 18) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

  const optional = coff + 20

  file.writeUInt16LE(0x020b, optional) // PE32+
  file.writeUInt32LE(align(bundle.byteLength, FILE_ALIGNMENT), optional + 8) // initialized data
  file.writeBigUInt64LE(0x140000000n, optional + 24) // image base
  file.writeUInt32LE(SECTION_ALIGNMENT, optional + 32)
  file.writeUInt32LE(FILE_ALIGNMENT, optional + 36)
  file.writeUInt16LE(6, optional + 40) // major OS version
  file.writeUInt16LE(6, optional + 48) // major subsystem version
  file.writeUInt32LE(align(address + bundle.byteLength, SECTION_ALIGNMENT), optional + 56)
  file.writeUInt32LE(headers, optional + 60)
  file.writeUInt16LE(3, optional + 68) // console subsystem
  file.writeBigUInt64LE(0x100000n, optional + 72) // stack reserve
  file.writeBigUInt64LE(0x1000n, optional + 80) // stack commit
  file.writeBigUInt64LE(0x100000n, optional + 88) // heap reserve
  file.writeBigUInt64LE(0x1000n, optional + 96) // heap commit
  file.writeUInt32LE(16, optional + 108) // data directories

  const table = optional + optionalSize

  file.write('.bare', table, 8, 'ascii')
  file.writeUInt32LE(bundle.byteLength, table + 8) // virtual size
  file.writeUInt32LE(address, table + 12)
  file.writeUInt32LE(align(bundle.byteLength, FILE_ALIGNMENT), table + 16) // raw size
  file.writeUInt32LE(offset, table + 20)
  file.writeUInt32LE(0x40000040, table + 36) // CNT_INITIALIZED_DATA | MEM_READ

  bundle.copy(file, offset)

  return file
}

const bundle = app()

for (const target of targets) {
  const file = target.write(bundle, target.arch)
  const dir = path.join(__dirname, 'by-arch', target.name, 'app')

  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, target.binary), file)

  console.log(target.name + '/app/' + target.binary, file.byteLength + ' bytes')
}
