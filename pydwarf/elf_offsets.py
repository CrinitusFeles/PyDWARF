from pathlib import Path
from elftools.elf.elffile import ELFFile


KIND2TAG: dict[str, str] = {
    'struct': 'DW_TAG_structure_type',
    'union': 'DW_TAG_union_type',
    'typedef': 'DW_TAG_typedef',
}


def _validate_struct(struct):
    kind, name = 'typedef', struct
    if ' ' in struct:
        kind, name = struct.split(' ', 1)
        if kind not in {'struct', 'union', 'typedef'}:
            raise ValueError('Not a struct or union')
        if len(name.split()) > 1:
            name = name.split()[-1]
    return kind, name


def get_all_offsets_from_ELF(filename: Path | str, structs,
                             use_recursive: bool = False) -> dict[str, list[tuple]]:
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
        result = {}
        for struct, (kind, value) in zip(structs, names):
            cu, item = items[kind, value]
            offset2die = cu2offset2die[cu]
            if kind == 'DW_TAG_typedef':
                item = item.get_DIE_from_attribute('DW_AT_type')
            result[struct] = [
                (field_type, field_name, offset)
                for field_type, field_name, offset in get_offsets_from_DIE(item, offset2die, use_recursive)
            ]
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


def get_offsets_from_DIE(die, offset2die, use_recursive: bool, level=0):
    assert die.tag in {'DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_typedef'}, 'Unhandled main type: ' + die.tag
    # Union members all start at the same offset (at least I sure fucking hope so)
    offset = 0

    def calc_offset(die_child):
        loc = die_child.attributes['DW_AT_data_member_location'].value
        if isinstance(loc, list):
            l = loc[1:]
            if len(l) == 2:
                high = l[1] >> 1
                low = l[0] & 0x7F if (l[1] & 0x01) == 0 else l[0]
                offset = int.from_bytes(bytes([high, low]))
            else:
                offset = l[0]
        else:
            offset = loc
        return offset

    array_size = []
    for child in die.iter_children():
        if child.tag == 'DW_TAG_array_type':
            array_size.append(list(child.iter_children())[0].attributes['DW_AT_upper_bound'].value + 1)
            continue
        elif child.tag != 'DW_TAG_member':
            continue
        assert child.tag in 'DW_TAG_member', 'Unhandled child type: ' + child.tag
        if die.tag == 'DW_TAG_structure_type':
            # Struct members have different starting offsets
            offset = calc_offset(child)
        else:
            assert 'DW_AT_data_member_location' not in child.attributes, 'Union members can have starting offsets?!'


        if 'DW_AT_name' in child.attributes:
            value_name = child.attributes['DW_AT_name'].value.decode('ascii')
            if len(array_size) > 0:
                for size in array_size[::-1]:
                    value_name += f'[{size}]'
                array_size = []
            if 'DW_AT_bit_offset' in child.attributes:
                value_name += f': {child.attributes["DW_AT_bit_size"].value}'
            value_die = child.get_DIE_from_attribute('DW_AT_type')
            if 'DW_AT_name' in value_die.attributes:
                value_type = value_die.attributes['DW_AT_name'].value.decode('ascii')
            else:
                if 'DW_AT_type' in value_die.attributes:
                    p = value_die.get_DIE_from_attribute('DW_AT_type')
                    if 'DW_AT_name' in p.attributes:
                        v  = p.attributes['DW_AT_name']
                        value_type = v.value.decode('ascii')
                    else:
                        p2 = p.get_DIE_from_attribute('DW_AT_type')
                        if 'DW_AT_name' in p2.attributes:
                            v  = p2.attributes['DW_AT_name']
                            value_type = v.value.decode('ascii')
                        else:
                            value_type = ''
                else:
                    value_type = 'struct'

            yield f'{"    " * level}{value_type}', value_name, f'{"    " * level}+{offset}'
            if value_type == 'struct' and value_die.has_children:
                yield from get_offsets_from_DIE(value_die, offset, level=level+1,
                                                use_recursive=use_recursive)
            elif value_die.tag == 'DW_TAG_typedef' and use_recursive:
                p = value_die.get_DIE_from_attribute('DW_AT_type')
                if p.has_children:
                    yield from get_offsets_from_DIE(p, offset, level=level+1,
                                                    use_recursive=use_recursive)
        else:
            # Anonymous union or struct
            p = child.get_DIE_from_attribute('DW_AT_type')
            yield from get_offsets_from_DIE(p, offset2die, level=level+1,
                                            use_recursive=use_recursive)
            # child_type = offset2die[child.attributes['DW_AT_type'].value]
            # yield from get_offsets_from_DIE(child_type, offset2die, offset)


if __name__ == '__main__':
    filename: Path = Path.cwd() / 'GrADCS_MCU_FW.axf'
    # filename: Path = Path(__file__).parent / 'STM32_LoRa_v3.1.out.elf'
    search_offest_for: list[str] = [
        # "struct LoRa_setting",
        # "union RadioProtocol"
        "typedef struct TMI6_t"
    ]
    result: dict = get_all_offsets_from_ELF(filename, search_offest_for, use_recursive=True)
    for struct_name, data in result.items():
        print(struct_name)
        for field in data:
            field_str: str = f'{field[0]} {field[1]}'
            print(f'| {field_str:<35}| {field[2]:<12}|')
        print()