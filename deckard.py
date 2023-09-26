#!/usr/bin/env python3

import magic
import hashlib
import pefile
import ssdeep
import peid
import lief
import os.path
import sys
import argparse
import json
from datetime import datetime


def get_filetype(filename):
    filetype = magic.from_file(filename)
    return filetype


def scan_pe(filename):
    #
    # Create the results dict
    #
    results = {}
    #
    # Determine the file size
    #
    results['size'] = os.path.getsize(filename)
    #
    # Get the magic
    #
    filetype = magic.from_file(filename)
    results['magic'] = filetype
    #
    # Create the PE object
    #
    pe = pefile.PE(filename) 
    #
    # Get the MD5 hashes
    #
    sample_md5 = hashlib.md5()
    with open(filename, 'rb') as file:
        while True:
            chunk = file.read(sample_md5.block_size)
            if not chunk:
                break
            sample_md5.update(chunk)
    results['md5'] = sample_md5.hexdigest()
    #
    # Get the SHA1 hash
    #
    sample_sha1 = hashlib.sha1()
    with open(filename, 'rb') as file:
        while True:
            chunk = file.read(sample_sha1.block_size)
            if not chunk:
                break
            sample_sha1.update(chunk)
    results['sha1'] = sample_sha1.hexdigest()
    #
    # Get the SHA256 hash
    #
    sample_sha256 = hashlib.sha256()
    with open(filename, 'rb') as file:
        while True:
            chunk = file.read(sample_sha256.block_size)
            if not chunk:
                break
            sample_sha256.update(chunk)
    results['sha256'] = sample_sha256.hexdigest()
    #
    # Get the imphash
    #
    results['imphash'] = pe.get_imphash()
    #
    # Get the fuzzy hash
    #
    results['ssdeep'] = ssdeep.hash_from_file(filename)
    #
    # Get the richpe hash
    #
    rich_header = pe.parse_rich_header()
    if rich_header is None:
        results['rich_pe'] = None
    else:
        # Get list of @Comp.IDs and counts from Rich header
        # Elements in rich_fields at even indices are @Comp.IDs
        # Elements in rich_fields at odd indices are counts
        rich_fields = rich_header.get("values", None)
        if len(rich_fields) % 2 != 0:
            results['rich_pe'] = None
        else:
            # The Rich header hash of a file is computed by computing the md5 of the
            # decoded rich header without the rich magic and the xor key, but with
            # the dans magic. It can be used with yara hash.md5(pe.rich_signature.clear_data)
            sample_richpe = hashlib.md5()
            sample_richpe.update(rich_header["clear_data"])
            results['rich_pe'] = sample_richpe.hexdigest()
    #
    # Get the authentihash (SHA256)
    #
    pe_lief = lief.parse(filename)
    results['authentihash'] = pe_lief.authentihash(lief.PE.ALGORITHMS.SHA_256).hex()
    #
    # Get the compilation timestamp
    #
    t = pe.FILE_HEADER.TimeDateStamp
    timestamp = str(datetime.fromtimestamp(t))
    results['timestamp'] = timestamp
    #
    # Get the packer and compiler info
    #
    packers = peid.identify_packer(filename)
    results['packers'] = packers[0][1]
    #
    # Return the results
    #
    return results


def get_sections(filename):
    #
    # Create results dict
    #
    section_list = []
    #
    # Create the PE object
    #
    pe = pefile.PE(filename)
    #
    # Iterate sections
    #
    for section in pe.sections:
        s = {
            'name': section.Name.decode().rstrip('\x00'),
            'virtual_address': int(section.VirtualAddress),
            'virtual_size': int(section.Misc_VirtualSize),
            'raw_data_size': int(section.SizeOfRawData),
            'raw_data_pointer': hex(section.PointerToRawData),
            'characteristics': hex(section.Characteristics),
            'entropy': section.get_entropy(),
            'md5': section.get_hash_md5()
        }
        section_list.append(s)
    return section_list


def get_imports(filename):
    #
    # Create results and DLL dicts
    #
    results = {}
    #
    # Create the PE object
    #
    pe = pefile.PE(filename)
    #
    # Get the imports
    #
    for lib in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = lib.dll.decode('utf-8')
        func_list = []
        for func in lib.imports:
            # func_dict = {'function': func.name.decode('utf-8'), 'address': func.address}
            func_list.append(func.name.decode('utf-8'))
        results[dll_name] = func_list
    return results


def check_sample_file(filename):
    if os.path.exists(filename):
        if os.path.isfile(filename):
            return os.access(filename, os.R_OK)
        else:
            return False
        

def main():
    #
    # Process the command line arguments
    #
    parser = argparse.ArgumentParser(
        prog="deckard",
        description="PE executable static analyzer"
    )
    parser.add_argument('filename', help="The path to the sample file")
    parser.add_argument("-o", "--output", action='store', dest='outfile', help="Directs the output to a filename of your choice")
    args = parser.parse_args()
    sample = args.filename
    if args.outfile:
        outfile = args.outfile
    #
    # Initialize the result dict
    #
    result = {}
    #
    # Can we read the sample file?
    #
    if check_sample_file(sample) is False:
        print("Cannot open sample file", file=sys.stderr)
        exit(1)
    #
    # Process the file
    #
    result['name'] = sample
    result['file_type'] = get_filetype(sample)
    result['file_properties'] = scan_pe(sample)
    result['sections'] = get_sections(sample)
    result['imports'] = get_imports(sample)
    #
    # Write the results
    #
    if 'outfile' in locals():
        with open(outfile, 'w') as o:
            o.write(json.dumps(result, indent=4))
    else:
        print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()