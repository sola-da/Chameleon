#!/usr/bin/env python

'''
top-level file for generating the Chameleon test suite.
change 'METASPLOIT_TEST_DIR' to point out to the local directory that Metasploit stores the generated files.
change 'TEST_SUITE_DIR' to where you want to have the generated test suite stored.
don't touch MAX_POSSIBLE_OS_ARG_LIST_SIZE unless you get a argument list too long error. in that case reduce this number until it works.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''

import random
import subprocess
from subprocess import Popen, PIPE
import shutil
from os import makedirs, system, listdir, path
from sys import stdout

from testcases import enumerate_exploits, enumerate_shellcodes, enumerate_evasions
from testcases import expected_signals, translate, get_id
from util import md5, sha1, sha256
from db import DataBase


METASPLOIT_TEST_DIR = "~/.msf4/local"
TEST_SUITE_DIR = "~/Desktop/ChameleonSuite"
MAX_POSSIBLE_OS_ARG_LIST_SIZE = 120000

all_names = []
'''
returns a unique filename for each generated file that is
irrelevant of the payload, exploit, or the evasion used in it.
'''
def unique_pdf_filename():
    global all_names
    while True:
        fir = ["andromeda", "black-eye", "bode", "cartwheel", "cigar", "comet", "cosmos",
                "hoag", "magellanic", "mayall", "milky", "pinwheel", "sombrero", "sunflower",
                "tadpole", "whirlpool"
            ]
        sec = ["sun", "mercury", "venus", "earth", "mars", "jupiter", "saturn", "uranus", "neptune"]
        third = random.randint(0, 1000)
        name = fir[random.randint(0, len(fir)-1)] + "_" + \
            sec[random.randint(0, len(sec)-1)] + "_{0}.pdf".format(third)
        # keep track of all generated names in the current run of the program to make sure there's no duplicate
        if name not in all_names:
            all_names.append(name)
            return name
        else:
            unique_pdf_filename()



def supposed_num_of_tests():
    return len(enumerate_exploits()) * \
        len(enumerate_shellcodes()) * \
        len(enumerate_evasions())



# splits the final msf string from "run;" to "run;" so that it fits in the OS arg list.
def split(msf_str):
    batches = []
    length = 0
    while (length != -1): # while end of string not reached...
        while (length < MAX_POSSIBLE_OS_ARG_LIST_SIZE):
            length = msf_str.find ("run;", length+1)
            if (length == -1):
                batches.append(msf_str)
                return batches
        batches.append(msf_str[:length + len("run;")])
        msf_str = msf_str[length + len("run;"):]
        length = 0


'''
runs msfconsole with the given commands to generate the samples.
'exploit', and 'shell' are for logging purpose only.
'''
def run_metasploit(ms_cli_commands, exploit, shell):
    no_error = True
    old_num_of_tests = 0
    for msf_str in split(ms_cli_commands):
        # it's important to append "exit" to the MS CLI command.
        msf_str += "exit;"
        print "Please wait while Metasploit is running for {0} tests (exploit: {1}" \
            ", shell: {2})...".format(
            msf_str.count("run"), exploit, shell)
        ms = Popen(["msfconsole",
            "-x",
            msf_str],
            stdout = PIPE,
            stderr = PIPE)
        out_splitted = ms.communicate()[0].split("\n")
        for line in out_splitted:
            if "[-]" in line:
                print line
                no_error = False
        print "Number of tests generated successfully: {0}".format(
            len(listdir(METASPLOIT_TEST_DIR)) - old_num_of_tests)
        old_num_of_tests = len(listdir(METASPLOIT_TEST_DIR))



'''
after being generated, samples are categorized based on their payload
and exploit in different directories.
this function returns the category (payload + exploit) of each sample
based on its filename.
'''
def dest_dir_and_name(base_dir, filename, exploit, shell):
    if not path.exists(path.join(base_dir, exploit)):
        makedirs(path.join(base_dir, exploit))

    if not path.exists(path.join(base_dir, exploit, shell)):
        makedirs(path.join(base_dir, exploit, shell))

    return path.join(base_dir, exploit, shell, filename)


'''
with the new way of storing evasions, this function would be handy in
translating the evasion from the old format (filename-based) to the new
format (db-based). the functionality of this function can alternatively be implemented
in 'testcases.py'.
'''
def get_evasions(filename):
    filename = path.splitext(filename)[0]
    result = []
    evasions = filename.split("___")[1].split("---")[1:]
    if evasions:
        for evasion in evasions:
            try:
                evasion_name = evasion.split("--")[0]
                args = evasion.split("--")[1]
                evasion_whole = [evasion_name]
                if args:
                    for arg in args.split("-"):
                        evasion_whole.append(arg)
                result.append(evasion_whole)
            except IndexError:
                result.append([evasion_name])
    return result




def generate(clean_dir, clean_db):
    shutil.rmtree(METASPLOIT_TEST_DIR)
    makedirs(METASPLOIT_TEST_DIR)
    if (clean_dir == "" or clean_dir == "yes" or clean_dir == "y" or clean_dir == "true"):
        if path.exists(TEST_SUITE_DIR):
            shutil.rmtree(TEST_SUITE_DIR)
            makedirs(TEST_SUITE_DIR)
    db = DataBase(clean_db)
    print "Test suite size: {0}".format(supposed_num_of_tests())
    print "Test suite directory: {0}".format(TEST_SUITE_DIR)
    print "Metasploit local samples directory: {0}".format(METASPLOIT_TEST_DIR)
    # for each single combination of exploit, shellcode, and evasion...
    for exploit in enumerate_exploits():
        for shell in enumerate_shellcodes():
            batch_msf_str = ""
            filenames_oracle = []
            print "Storing evasions in the DB (pre-generate)..."
            for evasion in enumerate_evasions():
                evs_arr = []
                sample_filename = unique_pdf_filename()
                (msf_str, oracle_inst) = translate(exploit, shell, evasion, sample_filename)
                batch_msf_str += msf_str
                filenames_oracle.append([sample_filename, oracle_inst])
                evs_arr = get_evasions(oracle_inst) # bridge from the legacy way of storing evasions to the new way
                signals = expected_signals(shell)
                outcome = "malicious"
                db.store_sample(
                    get_id(evasion), sample_filename, exploit, shell, evs_arr, signals, outcome)
                stdout.write('.')
                stdout.flush()
            print ""
            run_metasploit(batch_msf_str, exploit, shell) # exploit, and shell are passed for logging purporse only.
            print "Storing generated samples' hashes in the DB (post-generate)..."
            for filename, oracle in filenames_oracle:
                sample_abs_path = path.join(METASPLOIT_TEST_DIR, filename)
                # samples with 'steganography' evasion generate a png file that needs to be moved as well.
                steg_icon_filename = filename + ".png"
                steg_icon_abs_path = path.join(METASPLOIT_TEST_DIR, steg_icon_filename)
                db.store_sample_hash(filename, sha256(sample_abs_path), sha1(sample_abs_path), md5(sample_abs_path))
                shutil.move(sample_abs_path,
                    dest_dir_and_name(TEST_SUITE_DIR, filename, exploit, shell))
                # write the oracle tester instructions in a separate text file with the same name as the sample filename
                with open(
                    dest_dir_and_name(TEST_SUITE_DIR, filename + ".txt", exploit, shell), "w") as f:
                    f.write(oracle)
                if (path.exists(steg_icon_abs_path)):
                    shutil.move(steg_icon_abs_path,
                        dest_dir_and_name(TEST_SUITE_DIR, steg_icon_filename, exploit, shell))
                stdout.write('.')
                stdout.flush()
            print ""



clean_dir = raw_input ("Clean the old test suite directory? (default: yes) ")
clean_db = raw_input ("Clean the old samples from the DB? (WARNING! results would be deleted as well.) (default: no) ")
generate(clean_dir, clean_db)
