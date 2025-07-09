# Overview

dasn1 is a tool for interacting with ASN.1 notation files, using the ASN.1 parser provided by Juptune.

This is currently WIP.

## Building

Tagged releases will have a linux build of dasn1 attached to it, e.g. TODO

If you want to build it manually then please perform the following steps:

```bash
your-package-manager install meson some-d-compiler

git clone https://github.com/Juptune/juptune
cd juptune
meson setup build -Ddefault_library=static
meson compile -C build dasn1

# You can move this wherever, it should be a static build
./build/tools/dasn1/dasn1 --help
```

## Usage

Currently dasn1 only supports a `print` command used for debugging, but the next step is for it to generate D code that can decode DER-encoded ASN.1 data.

### print

```
dasn1 print [--no-semantics] [--show-memory-usage] <files and directories>
```

This command will parse all of the provided files, print out any errors, and print out dasn1's interpretation of the file as ASN.1 notation.

This command is used to debug how well Juptune's ASN.1 parser is working for a given input, but otherwise has no super practical uses.

Args:

* `--no-semantics` = The parser will not run (most) semantic passes, this can be useful for inputs that require other modules that don't exist/were not passed into dasn1.
* `--show-memory-usage` = The amount of memory in bytes used for Juptune's AST and IR nodes will be printed, useful for debugging.
* `<files>` = Free standing ASN.1 notation files to parse.
* `<directories>` = Any input ending with a slash (`/`) will be treated as a directory. All files in the directory (and subdirectories of any depth) that end with the `.asn1` extension will be parsed.

Output:

* If any errors are encountered, appropriate human friendly error messages will be printed to stdout (TODO: change to stderr). dasn1 will return status code `1` as well.
* The re-rendered ASN.1 notation for all inputs will be printed to stdout. A partial printing may still occur if errors are encountered.