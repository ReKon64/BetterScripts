#!/usr/bin/env python3
import argparse
import re
import os
from colorama import init, Fore, Style
# Planned Accepted & Generated Formats:
# John Smith DONE
# john.smith
# j.smith
# JohnSmith

# Generated but not accepted formats
# acceptedformat@domain.tld

init(autoreset=True) # Colorama colour autoreset

parser = argparse.ArgumentParser(
prog = "rubedo.py",
description = "Automagically transmute name lists",)
parser.add_argument('-f', '--filepath', help = 'Path to a file with the accepted formats', action='store', required=True)
parser.add_argument('-d', '--domain', help = 'Domain to append', action='store')
parser.add_argument('-v', '--verbose', help = 'More verbose output', action='store')
parser.add_argument('-o', '--outfile', help = 'Outfile base name to write to')

#        if filepath and (not os.path.isfile(file_path) or not os.access(file_path, os.R_OK)):
#           raise FileNotFoundError(f"File not found or no permission to read: {file_path}")


args = parser.parse_args()

with open(args.filepath, "r") as f:
    filecontent = f.read()

class Transmuter:
    def __init__(self,filecontent=filecontent,domain=args.domain,verbose=args.verbose,outfile=args.outfile):

        self.filecontent = filecontent
        self.domain   = domain 
        self.verbose  = verbose
        self.outfile  = outfile

# Deletes all Spaces and Tabs
    def clearSpace(self):
        result = re.sub(r'[ \t]+', '', self.filecontent)
        
        self.CS = result
        with open(f'{self.outfile}JohnSmith.tr', 'w') as f:
            f.write(result)
        return result

    def toHashmap(self):
        lines = self.filecontent.splitlines()
        result_map = {}
        line_id = 1
        
        for line in lines:
            uppercase_count = len(re.findall(r'[A-Z]', line))

            if uppercase_count > 1:
                # Split the line by spaces, but only on the first two capital letters
                split_result = re.sub(r"([A-Z])", r" \1", line, count=2).split()
                
                if len(split_result) >= 2:
                    result_map[line_id] = (split_result[0], split_result[1])
                    line_id += 1
                else:
                    print(f"{Style.BRIGHT}{Fore.RED}Warning: Skipping line '{line}' (unable to split into two parts).")
            else:
                print(f"Warning: Skipping line '{line}' (not enough uppercase letters).")

    
        self.result_map = result_map
        return result_map

    def nsurname(self):
        nsurnames = []
        for key in self.result_map:
            nsurnames.append(self.result_map[key][0][0].lower() + self.result_map[key][1].lower())
        
        with open(f'{self.outfile}jsmith.tr', 'w') as f:
            f.writelines(f"{item}\n" for item in nsurnames)

        self.nsurnames = nsurnames
        return nsurnames

    def nDOTsurname(self):
        nDOTsurnames = []
        for key in self.result_map:
            nDOTsurnames.append(self.result_map[key][0][0].lower() + '.' + self.result_map[key][1].lower())
        
        self.nDOTsurnames = nDOTsurnames
        return nDOTsurnames
    
    def appendDomain(self):
        nsdom = []
        nDOTsdom = []

        if self.nsurnames:
            for entry in self.nsurnames:
                nsdom.append(f'{entry}@{self.domain}')
            
            with open(f'{self.outfile}jsmithAT{self.domain}.tr', 'w') as f:
                f.writelines(f"{item}\n" for item in nsdom)
        
        if self.nDOTsurnames:
            for entry in self.nDOTsurnames:
                nDOTsdom.append(f'{entry}@{self.domain}')

            with open(f'{self.outfile}j.smithAT{self.domain}.tr', 'w') as f:
                f.writelines(f"{item}\n" for item in nsdom)

        return nsdom,nDOTsdom


test = Transmuter()
print(test.clearSpace())
print(test.toHashmap())
test.nsurname()
print(test.nDOTsurname())
print(test.appendDomain())


