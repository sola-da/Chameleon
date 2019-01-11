#!/usr/bin/env python

'''
top-level file for assessing an analyzer's capability in coping with evasions.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''

import json
import shutil
from os import makedirs, getcwd, path

from evasion_pair_enumerator import EvasionMiner
from fp_ratio_recall_miner import FPRatioRecallMiner

from testcases import EVASION_ALL, EVASION_ALL_DYNAMIC, EVASION_ALL_STATIC, EVASION_ALL_HYBRID
from testcases import enumerate_exploits, EXPLOIT_ALL, EXPLOIT_TOOLBUTTON, EXPLOIT_COOLTYPE
from testcases import enumerate_shellcodes, SHELLCODE_ALL, SHELLCODE_REVERSE_BIND, SHELLCODE_POWERSHELL, SHELLCODE_EXIT
from testcases import single_evasion_testcases, get_base_evasion

from analyzers_list import static_analyzers, dynamic_analyzers
from analyzers_list import all_analyzer_that_scanned_toolbutton, all_analyzer_that_scanned_cooltype
from analyzers_list import analyzers_that_scanned_any


RESULTS_DIR = path.join(getcwd(), "results")
ANALYZERS_RES_DIR = path.join(RESULTS_DIR, "analyzers")
EXPLOITS_RES_DIR = path.join(RESULTS_DIR, "exploits")
SHELLCODES_RES_DIR = path.join(RESULTS_DIR, "shellcodes")

if (path.exists(RESULTS_DIR)):
	shutil.rmtree(RESULTS_DIR)

makedirs(RESULTS_DIR)
makedirs(ANALYZERS_RES_DIR)
makedirs(EXPLOITS_RES_DIR)
makedirs(SHELLCODES_RES_DIR)

# FP ratio and recall
FPRatioRecallMiner().mine_for_analyzers(
	analyzers=analyzers_that_scanned_any(),
	csv_filename=path.join(RESULTS_DIR, "fp_ratio_recall.csv")
	)
print "FP Ratio Recall done."

# added effectiveness for all analyzers
EvasionMiner().added_effectiveness(
	analyzers=analyzers_that_scanned_any(),
	csv_filename=path.join(RESULTS_DIR, "added_effectiveness_all_analyzers.csv")
	)
print "Added effectiveness for all analyzers done."

# projection of effectiveness for static analyzers
overall_static_analyzers_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=static_analyzers(),
	csv_filename=path.join(RESULTS_DIR, "static_analyzers_projection.csv")
	)
print "Analyzer projection for static analyzers done."

# projection of effectiveness for dynamic analyzers
overall_dynamic_analyzers_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=dynamic_analyzers(),
	results_order="given_order",
	given_order=overall_static_analyzers_res,
	csv_filename=path.join(RESULTS_DIR, "dynamic_analyzers_projection.csv")
	)
print "Analyzer projection for dynamic analyzers done."

# best case effectiveness averaged over all analyzers
best_eff = open(path.join(RESULTS_DIR, "best_eff_average.csv"), "w")
best_eff.write("Evasion, Static Analyzers, Dynamic Analyzers")
best_eff.write("\n")
best_eff_static_analyzers = EvasionMiner.best_case_effectiveness(overall_static_analyzers_res)
best_eff_dynamic_analyzers = EvasionMiner.best_case_effectiveness(overall_dynamic_analyzers_res)
for evasion in best_eff_static_analyzers:
	best_eff.write("{0}, {1}, {2}".format(
		evasion, 
		best_eff_static_analyzers[evasion],
		best_eff_dynamic_analyzers[evasion]
	))
	best_eff.write("\n")
best_eff.close()
print "Average best case Effectiveness done."

# worst case counter-effectiveness averaged over all analyzers
worst_counter_eff = open(path.join(RESULTS_DIR, "worst_counter_eff_average.csv"), "w")
worst_counter_eff.write("Evasion, Static Analyzers, Dynamic Analyzers")
worst_counter_eff.write("\n")

worst_counter_eff_static_analyzers = EvasionMiner.worst_case_counter_effectiveness(
	overall_static_analyzers_res)

worst_counter_eff_dynamic_analyzers = EvasionMiner.worst_case_counter_effectiveness(
	overall_dynamic_analyzers_res)

for evasion in worst_counter_eff_static_analyzers:
	worst_counter_eff.write("{0}, {1}, {2}".format(
		evasion, 
		worst_counter_eff_static_analyzers[evasion],
		worst_counter_eff_dynamic_analyzers[evasion]
	))
	worst_counter_eff.write("\n")
worst_counter_eff.close()
print "Average worst case Counter-effectiveness done."

# projection of effectiveness for exploits on all analyzers
exp_toolbutton_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=all_analyzer_that_scanned_toolbutton(),
	exploits=EXPLOIT_TOOLBUTTON,
	csv_filename=path.join(EXPLOITS_RES_DIR, EXPLOIT_TOOLBUTTON + "_projection.csv")
	)
print "Exploit projection for {0} done.".format(EXPLOIT_TOOLBUTTON)

exp_cooltype_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=all_analyzer_that_scanned_cooltype(),
	exploits=EXPLOIT_COOLTYPE,
	results_order="given_order",
	given_order=exp_toolbutton_res,
	csv_filename=path.join(EXPLOITS_RES_DIR, EXPLOIT_COOLTYPE + "_projection.csv")
	)
print "Exploit projection for {0} done.".format(EXPLOIT_COOLTYPE)

# projection of effectiveness for shellcodes on all analyzers
shell_reverse_bind_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=analyzers_that_scanned_any(),
	shellcodes=SHELLCODE_REVERSE_BIND,
	csv_filename=path.join(SHELLCODES_RES_DIR, SHELLCODE_REVERSE_BIND + "_projection.csv")
	)
print "Shellcode projection for {0} done.".format(SHELLCODE_REVERSE_BIND)

shell_powershell_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=analyzers_that_scanned_any(),
	shellcodes=SHELLCODE_POWERSHELL,
	results_order="given_order",
	given_order=shell_reverse_bind_res,
	csv_filename=path.join(SHELLCODES_RES_DIR, SHELLCODE_POWERSHELL + "_projection.csv")
	)
print "Shellcode projection for {0} done.".format(SHELLCODE_POWERSHELL)

shell_exit_res = EvasionMiner().mine_evasion_effectiveness(
	analyzers=analyzers_that_scanned_any(),
	shellcodes=SHELLCODE_EXIT,
	results_order="given_order",
	given_order=shell_reverse_bind_res,
	csv_filename=path.join(SHELLCODES_RES_DIR, SHELLCODE_EXIT + "_projection.csv")
	)
print "Shellcode projection for {0} done.".format(SHELLCODE_EXIT)

# projection of effectiveness for dynamic evasions on each analyzer
avg_eff = open(path.join(RESULTS_DIR, "dynamic_evasions_projection.csv"), "w")
avg_eff.write("Analyzer, Average Effectiveness")
avg_eff.write("\n")
for analyzer in analyzers_that_scanned_any():
	dynamic_evasions_res = EvasionMiner().mine_evasion_effectiveness(
		analyzers=analyzer,
		evasions=EVASION_ALL_DYNAMIC
	)
	avg_eff.write("{0}, {1}".format(analyzer, EvasionMiner.average(dynamic_evasions_res)))
	avg_eff.write("\n")
	print "Dynamic evasions projection for {0} done.".format(analyzer)
avg_eff.close()

# projection of effectiveness for static evasions on each analyzer
avg_eff = open(path.join(RESULTS_DIR, "static_evasions_projection.csv"), "w")
avg_eff.write("Analyzer, Average Effectiveness")
avg_eff.write("\n")
for analyzer in analyzers_that_scanned_any():
	static_evasions_res = EvasionMiner().mine_evasion_effectiveness(
		analyzers=analyzer,
		evasions=EVASION_ALL_STATIC
	)
	avg_eff.write("{0}, {1}".format(analyzer, EvasionMiner.average(static_evasions_res)))
	avg_eff.write("\n")
	print "Static evasions projection for {0} done.".format(analyzer)
avg_eff.close()

print "Finito!"
