import os
import hashlib
import pefile #parses PE file
import re #REGEX
from config import Config

class PEAnalyzer:
    def __init__(self): #initialize
        self.pe = None 
        self.filepath = None
        self.hashes = {}

    def load_file(self, filepath):
        self.filepath = filepath #set the file path
        self.pe = pefile.PE(filepath) #load the file using pefile
        self._compute_hashes() 
        
        return {
            'basic_info': self._get_basic_info(),
            'hashes': self.hashes,
            'pe_info': self._get_pe_info(),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'strings': self.extract_strings()
        }

    #it reads the file as a binary and computes the hashes using hashlib library
    def _compute_hashes(self):
        with open(self.filepath, 'rb') as f:
            data = f.read()
        self.hashes = {
            'MD5': hashlib.md5(data).hexdigest(),
            'SHA1': hashlib.sha1(data).hexdigest(),
            'SHA256': hashlib.sha256(data).hexdigest(),
        }

    #File name and size is calculated using OS library as it convertes bits into bytes
    #type: 32 means that this sample is 32 bit and targets 32 bits computers
    # 64 means that this sample is 64 bit and targets 64 bits computers
    def _get_basic_info(self):
        return {
            'Filename': os.path.basename(self.filepath),
            'Size': f"{os.path.getsize(self.filepath):,} bytes",
            'Type': 'PE32' if self.pe.OPTIONAL_HEADER.Magic == 0x10b else 'PE32+'
        }
    
    #Entry point is the address where the program starts executing
    #Image base is the address where the program is loaded into memory
    #Sections are the different parts of the program, like code, data, etc.
    #Number of sections is the number of different parts of the program
    #that are loaded into memory
    #The pefile library parses the PE file and extracts this information
    def _get_pe_info(self):
        return [
            f"Entry Point: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}",
            f"Image Base: {hex(self.pe.OPTIONAL_HEADER.ImageBase)}",
            f"Sections: {self.pe.FILE_HEADER.NumberOfSections}"
        ]

    #Sections are the different parts of the program, like code, data, etc.
    #Each section has a name, virtual address where it is located, virtual size, and raw size
    #The pefile library parses the PE file and extracts this information
    #The section name is decoded from bytes to string and stripped of null characters
    #section are like code(imports and exports functions), data(like strings), etc.
    def _get_sections(self):
        sections = []
        for section in self.pe.sections:
            sections.append({
                'name': section.Name.decode(errors='ignore').strip('\x00'),
                'virtual_addr': hex(section.VirtualAddress), #address where the section is located in memory
                'virtual_size': hex(section.Misc_VirtualSize),#size when section is loaded into memory can be more as External fragmentation 
                'raw_size': hex(section.SizeOfRawData) #Real size of the section in the file
            })
        return sections

    #imports are the functions that the program uses from other DLLs (I need this)
    def _get_imports(self):
        imports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'): #kol wa7da leha attribute da y3rfak 2no import, Dy btrag3 list
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore') #kol import bykon maktoub 3ndha 2lDLL
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode(errors='ignore'))
                    else:
                        functions.append(f"Ordinal {imp.ordinal}")
                imports.append({'dll': dll_name, 'functions': functions})
        return imports

    #exports are the functions that the program provides to other DLLs (You can use this)
    def _get_exports(self):
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode(errors='ignore') if exp.name else f"Ordinal {exp.ordinal}"
                addr = hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)
                exports.append({'name': name, 'address': addr})
        return exports
    
    #for string filtering, we use regex to find all strings in the file
    def extract_strings(self, min_length=5, filter_name="All"):
        with open(self.filepath, "rb") as f:
            data = f.read()

        all_strings = re.findall(rb"[ -~]{%d,}" % min_length, data) #[ -~] all printable ascii chars
        pattern = Config.FILTERS.get(filter_name)

        if pattern: #if yes make filter
            return [s.decode(errors='ignore') for s in all_strings if pattern.search(s)]
        return [s.decode(errors='ignore') for s in all_strings] 