# PyDWARF

Command line interface for recursive calculation offsets in C structs.

## Installation

```
uv install git+https://github.com/CrinitusFeles/PyDWARF
```

or

```
pip install git+https://github.com/CrinitusFeles/PyDWARF
```

## Usage

``` bash
usage: python pydwarf [-h] [-l LABELS_INDENT] [-k OFFSET_INDET] [-d MAX_DEPTH] [-o CSV_OUTPUT_FILENAME] [-f OUTPUT_FORMAT] [-t TABLE_FORMAT] elf_filepath struct_name [struct_name ...]

Calculate C struct offset recusively.

positional arguments:
  elf_filepath          Path to .elf or .axf
  struct_name           name of struct, e.g.: typedef struct MyStruct

options:
  -h, --help            show this help message and exit
  -l LABELS_INDENT, --labels_indent LABELS_INDENT
                        indent for labels
  -k OFFSET_INDET, --offset_indet OFFSET_INDET
                        indent for offsets
  -d MAX_DEPTH, --max_depth MAX_DEPTH
                        indent for offsets
  -o CSV_OUTPUT_FILENAME, --csv_output_filename CSV_OUTPUT_FILENAME
                        filename for csv output
  -f OUTPUT_FORMAT, --output_format OUTPUT_FORMAT
                        output format: ["table", "struct", "json"]
  -t TABLE_FORMAT, --table_format TABLE_FORMAT
                        table format: ['plain', 'simple', 'grid', 'pipe', 'orgtbl', 'rst', 'mediawiki', 'github', 'latex', 'latex_raw', 'latex_booktabs', 'latex_longtable', 'tsv']
```

Example
``` bash
python pydwarf ./my_compiled.axf typedef struct MyEnormousStruct
```



