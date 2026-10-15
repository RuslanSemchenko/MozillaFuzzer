# MozillaFuzzer (Grizzly + Domato)

A DOM fuzzing environment for **Mozilla Firefox** integrating Mozilla's [Grizzly](https://github.com/MozillaSecurity/grizzly) framework with Google Project Zero's [Domato](https://github.com/googleprojectzero/domato) grammar-based generation engine.

## Overview

- **`grz_domato/`**: Grizzly adapter (`DomatoAdapter`) implementing `grizzly.adapter.Adapter` to generate test cases in-process using Domato.
- **`domato/`**: Grammar-based DOM generator supporting HTML, CSS, JavaScript, SVG, and MathML.
- **`fuzz.bat`**: Windows batch script to launch the Grizzly fuzzer against a Firefox binary.

## Prerequisites

- Python 3.14 (default)
- [Grizzly Framework](https://github.com/MozillaSecurity/grizzly) (`pip install grizzly-framework`)
- Firefox build (Debug or ASan build recommended for fuzzing)

## Installation

Install `grz-domato` in editable mode:

```bash
pip install -e .
```

Verify that the Grizzly adapter is recognized:

```bash
grizzly --list-adapters
```

You should see `domato` listed among available adapters.

## Usage

### Using the Batch Script (`fuzz.bat`)

Run with default Firefox path or specify arguments:

```cmd
fuzz.bat
```

Or pass custom Firefox binary path and runtime:

```cmd
fuzz.bat "C:\path\to\firefox.exe" 7200
```

### Running Directly via Grizzly CLI

```bash
python -m grizzly --runtime 360000 -o results "C:\path\to\firefox.exe" domato
```

## License

- Adapter code (`grz_domato/`): Mozilla Public License 2.0 (MPL-2.0)
- Domato generator (`domato/`): Apache License 2.0
