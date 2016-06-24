#!/usr/bin/python

import re, sys
import argparse

parser = argparse.ArgumentParser( description='Scan rtfFile and dumps embedded exe')
parser.add_argument('rtfFile', default=sys.stdout, type=argparse.FileType('r'), help='rtf File to Scan')
parser.add_argument("-d", dest="dumpDir",metavar="dumpDir",default="./",type=str,help="Dump Dir")
args = parser.parse_args()

destFileName = "dumpedFromRft.exe"

content = args.rtfFile.read()
args.rtfFile.close()

print("")
try:
    start = content.index("MZ\x90\x00")
except ValueError:
    start=-1
    print("[ ] MZ header Not Found")
    
if start != -1 :
    print("MZ Header found at offset "+hex(start))
    
    size = int(content[start-3:start].encode("hex"),16)
    print("File size : "+str(size/1024)+" ko.\n")

    try:
        FileNamesAndLocations = re.findall("[^\x00]*\.[^\x00]*",content[start-100:start])
    except:
        print("\n/!\ Something went wrong while searching original file names\n")

    if len(FileNamesAndLocations) > 0:
        print("Potential file name and location")
        for filename in FileNamesAndLocations:
            print("\t"+filename)
        
        try:
            destFileName = FileNamesAndLocations[0]
            destFileName = destFileName.split("\\")[-1]
        except:
            pass

        print("\nDumping exe to "+args.dumpDir+destFileName)
        
        try :
            f=open(args.dumpDir+destFileName,"w")
            f.write(content[start:start+size])
            f.close()
        except:
            print("\n/!\ Something went wrong while dumping the exe\n")
print("")
