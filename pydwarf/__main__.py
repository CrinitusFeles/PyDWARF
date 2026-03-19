import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Literal
from elftools.elf.elffile import ELFFile
from tabulate import tabulate


KIND2TAG: dict[str, str] = {
    'struct': 'DW_TAG_structure_type',
    'union': 'DW_TAG_union_type',
    'typedef': 'DW_TAG_typedef',
}


@dataclass
class Field:
    type_val: str
    level: int
    label: str
    offset: int
    bits: str | None = None
    array: str = ''



def _validate_struct(struct):
    kind, name = 'typedef', struct
    if ' ' in struct:
        kind, name = struct.split(' ', 1)
        if kind not in {'struct', 'union', 'typedef'}:
            raise ValueError('Not a struct or union')
        if len(name.split()) > 1:
            name = name.split()[-1]
    return kind, name


def get_all_offsets_from_ELF(filename: Path | str, structs) -> dict[str, list[Field]]:
    # Do argument validation at the beginning, so that if there's a problem, we don't have to wait for the file to parse first
    names = []
    for struct in structs:
        kind, name = _validate_struct(struct)
        names.append((KIND2TAG[kind], name.encode('ascii')))

    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        dwarf = elffile.get_dwarf_info()
        items = get_items_from_DWARF(dwarf, names=set(names))
        if not items:
            return {}
        cus = {cu for cu, item in items.values()}
        cu2offset2die = {
            cu: {die.offset: die for die in cu.iter_DIEs()}
            for cu in cus
        }
    result: dict[Any, list[Field]] = {}
    for struct, (kind, value) in zip(structs, names):
        cu, item = items[kind, value]
        offset2die = cu2offset2die[cu]
        if kind == 'DW_TAG_typedef':
            item = item.get_DIE_from_attribute('DW_AT_type')

        fields = []
        for field in get_offsets_from_DIE(item, offset2die):
            fields.append(field)
        result[struct] = fields
    return result



def find_item_from_DWARF(dwarf, tag, name):
    items = get_items_from_DWARF(dwarf, names={(tag, name)})
    if items:
        item, = items.values()
        return item


def get_items_from_DWARF(dwarf, tags=None, names=None):
    assert bool(tags) != bool(names), 'Must give either tags or names (but not both)'
    if names:
        tags = {tag for tag, name in names}

    found = {}
    for cu in dwarf.iter_CUs():
        die = cu.get_top_DIE()
        for child in die.iter_children():
            if child.tag not in tags:
                continue
            attr = child.attributes.get('DW_AT_name')
            if attr is None:
                continue
            name = (child.tag, attr.value)
            # print(attr.value)
            if names is None or name in names:
                # assert name not in found, 'Duplicate DWARF item'
                found[name] = (cu, child)
    return found


def calc_offset(die_child):
    loc = die_child.attributes['DW_AT_data_member_location'].value
    if isinstance(loc, list):
        s = loc[1:]
        if len(s) == 2:
            high = s[1] >> 1
            low = s[0] & 0x7F if (s[1] & 0x01) == 0 else s[0]
            offset = int.from_bytes(bytes([high, low]))
        else:
            offset = s[0]
    else:
        offset = loc
    return offset


def get_offsets_from_DIE(die, offset2die, level=0):
    assert die.tag in {'DW_TAG_structure_type', 'DW_TAG_union_type',
                       'DW_TAG_typedef', 'DW_TAG_enumeration_type'}, 'Unhandled main type: ' + die.tag
    # Union members all start at the same offset (at least I sure fucking hope so)
    offset = 0
    array_size = []
    for child in die.iter_children():
        if child.tag == 'DW_TAG_array_type':
            array_size.append(list(child.iter_children())[0].attributes['DW_AT_upper_bound'].value + 1)
            continue
        elif child.tag != 'DW_TAG_member':
            continue

        field = Field(type_val='', level=level, label='', offset=0)

        if die.tag == 'DW_TAG_structure_type':
            # Struct members have different starting offsets
            field.offset = calc_offset(child)
        elif die.tag == 'DW_TAG_enumeration_type':
            field.type_val = 'enum'

        flag = False
        if 'DW_AT_name' in child.attributes:
            field.label = child.attributes['DW_AT_name'].value.decode('ascii')
            if len(array_size) > 0:
                for size in array_size[::-1]:
                    field.array += f'[{size}]'
                array_size = []
            if 'DW_AT_bit_offset' in child.attributes:
                field.bits = f': {child.attributes["DW_AT_bit_size"].value}'

            types = []
            if 'DW_AT_name' in child.attributes:
                while 'DW_AT_type' in child.attributes:
                    child = child.get_DIE_from_attribute('DW_AT_type')
                    if 'DW_AT_name' in child.attributes:
                        types.append(child.attributes['DW_AT_name'].value.decode('ascii'))
                        field.type_val = types[0]
                    if child.tag == 'DW_TAG_structure_type':
                        if field.type_val == '':
                            field.type_val = 'struct'
                        flag = True
                        yield field
                        yield from get_offsets_from_DIE(child, offset, level=level+1)
            else:  # arrays
                while 'DW_AT_name' not in child.attributes and 'DW_AT_type' in child.attributes:
                    child = child.get_DIE_from_attribute('DW_AT_type')
                if 'DW_AT_name' in child.attributes:
                    field.type_val = child.attributes['DW_AT_name'].value.decode('ascii')
            if not flag:
                yield field
        else:
            # Anonymous union or struct
            p = child.get_DIE_from_attribute('DW_AT_type')
            yield from get_offsets_from_DIE(p, offset2die, level=level+1)


def to_string(result: dict[str, list[Field]],
              labels_indent: int,
              offset_indet: int,
              output_format: Literal['table', 'struct', 'json'],
              csv_output_filename: str | None = None,
              max_depth: int = 99,
              table_format: Literal['plain', 'simple', 'grid', 'pipe',
                                    'orgtbl', 'rst', 'mediawiki', 'github',
                                    'latex', 'latex_raw', 'latex_booktabs',
                                    'latex_longtable', 'tsv'] = 'grid',
              ):
    max_depth = 1 if max_depth < 1 else max_depth
    def to_columns(field: Field, output_format: Literal['struct', 'table']):
        prefix1 = "⠀" * labels_indent if output_format == 'struct' else ""
        prefix2 = "// " if output_format == 'struct' else ""
        bits: str = f'{field.bits}' if field.bits else ''
        array = f'{field.array}' if field.array else ''
        first_column: str = f'{prefix1}{" " * labels_indent * field.level} '\
                            f'{field.type_val} {field.label}{bits}{array}'
        second_column: str = f'{prefix2}{" " * offset_indet * field.level}+{field.offset}'
        return first_column, second_column

    output: list[str] = []
    table: list[tuple[str, str]] = []
    for struct_name, data in result.items():
        if output_format == 'table':
            table = [to_columns(field, output_format) for field in data
                                            if field.level < max_depth]
            output.append(tabulate(table, headers=[struct_name, 'offsets'],
                           tablefmt=table_format, disable_numparse=True,
                           stralign='left', preserve_whitespace=True))  # type: ignore
        elif output_format == 'struct':
            table = [to_columns(field, output_format) for field in data
                     if field.level < max_depth]
            output.append(tabulate(table, headers=[f'{struct_name} {{', ''],
                           tablefmt='plain', disable_numparse=True,
                           stralign='left', preserve_whitespace=True) + '}')  # type: ignore
        elif output_format == 'json':
            data = {key: [asdict(v) for v in val] for key, val in result.items()}
            output.append(json.dumps(data, indent=labels_indent))
        else:
            print('incorrect output_format')
            return ''
        if csv_output_filename is not None:
            csv_data: str = f'{struct_name};offsets\n'
            csv_data += '\n'.join([';'.join(line) for line in table])
            with open(Path.cwd() / csv_output_filename, 'w+', encoding='utf-8') as file:
                file.write(csv_data)
    return '\n\n'.join(output)


table_formats: list[str] = ["plain", "simple", "grid", "pipe", "orgtbl", "rst",
                            "mediawiki", "github", "latex", "latex_raw",
                            "latex_booktabs", "latex_longtable", "tsv"]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Calculate C struct offset recusively.')
    parser.add_argument('elf_filepath', type=str,
                        help='Path to .elf or .axf')
    parser.add_argument('struct_name', type=str, nargs='+',
                        help='name of struct, e.g.: typedef struct MyStruct')
    parser.add_argument('-l', '--labels_indent', type=int, default=4,
                        help='indent for labels')
    parser.add_argument('-k', '--offset_indet', type=int, default=0,
                        help='indent for offsets')
    parser.add_argument('-d', '--max_depth', type=int, default=99,
                        help='indent for offsets')
    parser.add_argument('-o', '--csv_output_filename', type=str, default=None,
                        help='filename for csv output')
    parser.add_argument('-f', '--output_format', type=str, default='table',
                        help='output format: ["table", "struct", "json"]')
    parser.add_argument('-t', '--table_format', type=str, default='pipe',
                        help=f'table format: {table_formats}')


    args = parser.parse_args()

    result: dict[str, list[Field]] = get_all_offsets_from_ELF(args.elf_filepath,
                                                              [' '.join(args.struct_name)])
    print(to_string(result,
                    labels_indent=args.labels_indent,
                    offset_indet=args.offset_indet,
                    output_format=args.output_format,
                    table_format=args.table_format,
                    csv_output_filename=args.csv_output_filename,
                    max_depth=args.max_depth))

