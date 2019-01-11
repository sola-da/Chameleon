'''
for each sample with payload p and exploit x, this module compares
the detection of a malware scanner for the sample with the detection
of the scanner for the sample + evasion to compute effectiveness.
in addition, this module computes other metrics such as best effectiveness
and worst counter effectiveness.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''

import sys
import operator
from os import path
from math import fabs
from collections import OrderedDict

from db import DataBase
from testcases import get_id

from testcases import no_testcase
from testcases import single_evasion_testcases
from testcases import all_testcases
from testcases import dynamic_testcases, static_testcases, dynamic_static
from testcases import dynamic_combined, static_combined, dynamic_static_combined

from testcases import get_base_evasion
from testcases import is_evasion_combined, constituents

from testcases import enumerate_evasions
from testcases import enumerate_exploits, EXPLOIT_ALL
from testcases import enumerate_shellcodes, SHELLCODE_ALL

from testcases import EVASION_ALL, EVASION_ALL_DYNAMIC, EVASION_ALL_STATIC, EVASION_ALL_HYBRID
from testcases import EVASION_DYNAMIC, EVASION_STATIC, EVASION_BOTH
from testcases import EVASION_DYNAMIC_COMBINED, EVASION_STATIC_COMBINED, EVASION_BOTH_COMBINED

class EvasionNotFoundException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class EvasionMiner:

    def __init__(self):
        self.db = DataBase()

        # overall eff and counter eff per analyzer aggregated over shellcode and exploit
        self.results = {}

        # overall added eff per analyzer aggregated over shellcode and exploit
        self.added_eff = {}

        # 'results' in the form of evasion effectiveness and counter-effectiveness percentage
        self.percentage_res = {}


    def _inline_init_percentage_res(self, evasion_type):
        for evasion in self.evasions(evasion_type):
            tc_id = get_id(evasion)
            self.percentage_res[tc_id] = {}
            self.percentage_res[tc_id]['type'] = evasion_type
            self.percentage_res[tc_id]['effectiveness'] = 0.0
            self.percentage_res[tc_id]['counter-effectiveness'] = 0.0
            self.percentage_res[tc_id]['added-effectiveness'] = 0.0


    def initialize_percentage_res(self, evasions):
        if (evasions == EVASION_ALL or evasions == EVASION_ALL_DYNAMIC):
            self._inline_init_percentage_res(EVASION_DYNAMIC)
            self._inline_init_percentage_res(EVASION_DYNAMIC_COMBINED)
        if (evasions == EVASION_ALL or evasions == EVASION_ALL_STATIC):
            self._inline_init_percentage_res(EVASION_STATIC)
            self._inline_init_percentage_res(EVASION_STATIC_COMBINED)
        if (evasions == EVASION_ALL or evasions == EVASION_ALL_HYBRID):
            self._inline_init_percentage_res(EVASION_BOTH)
            self._inline_init_percentage_res(EVASION_BOTH_COMBINED)


    # evasion effectiveness and counter-effectiveness
    def store_eff_counter_eff(self, result, testcase, tc_type):
        tc_id = get_id(testcase)
        try:
            # c.f. 'compare_detections' for the keys defined in 'result'
            self.results[tc_id]['evasion_type'] = tc_type
            if result['evasion_worked']:
                self.results[tc_id]['evasion_worked'] += 1
            if result['evasion_failed']:
                self.results[tc_id]['evasion_failed'] += 1
            if result['evasion_worsened']:
                self.results[tc_id]['evasion_worsened'] += 1
            if result['evasion_neutral']:
                self.results[tc_id]['evasion_neutral'] += 1
        except KeyError: # add the testcase if it was not found...
            # create a new entry
            self.results[tc_id] = {}
            # initialize the new entry
            self.results[tc_id]['evasion_type'] = tc_type
            self.results[tc_id]['evasion_worked'] = 0
            self.results[tc_id]['evasion_failed'] = 0
            self.results[tc_id]['evasion_worsened'] = 0
            self.results[tc_id]['evasion_neutral'] = 0
            # retry
            self.store_eff_counter_eff(result, testcase, tc_type)


    # evasion added effectiveness
    def has_added_eff(self, has_added_eff, testcase, tc_type):
        tc_id = get_id(testcase)
        try:
            self.added_eff[tc_id]['evasion_type'] = tc_type
            if has_added_eff:
                self.added_eff[tc_id]['added_eff'] += 1
        except KeyError: # add the testcase if it was not found...
            # create a new entry
            self.added_eff[tc_id] = {}
            # initialize the new entry
            self.added_eff[tc_id]['evasion_type'] = tc_type
            self.added_eff[tc_id]['added_eff'] = 0
            # retry
            self.has_added_eff(has_added_eff, testcase, tc_type)


    def compare_detections(self, ev_exc_outcome, ev_inc_outcome):
        if (ev_exc_outcome == "malicious" and
            ev_inc_outcome == "non-malicious"):
            return {
            'evasion_worked': True,
            'evasion_failed': False,
            'evasion_worsened': False,
            'evasion_neutral': False}

        if (ev_exc_outcome == "malicious" and
            ev_inc_outcome == "malicious"):
            return {
            'evasion_worked': False,
            'evasion_failed': True,
            'evasion_worsened': False,
            'evasion_neutral': False}

        if (ev_exc_outcome == "non-malicious" and
            ev_inc_outcome == "malicious"):
            return {
            'evasion_worked': False,
            'evasion_failed': False,
            'evasion_worsened': True,
            'evasion_neutral': False}

        if (ev_exc_outcome == "non-malicious" and
            ev_inc_outcome == "non-malicious"):
            return {
            'evasion_worked': False,
            'evasion_failed': False,
            'evasion_worsened': False,
            'evasion_neutral': True}


    # returns the the concrete evasions list according to 'evasion_type'
    def evasions(self, evasion_type):
        if evasion_type == EVASION_DYNAMIC:
            return dynamic_testcases()
        if evasion_type == EVASION_STATIC:
            return static_testcases()
        if evasion_type == EVASION_BOTH:
            return dynamic_static()
        if evasion_type == EVASION_DYNAMIC_COMBINED:
            return dynamic_combined()
        if evasion_type == EVASION_STATIC_COMBINED:
            return static_combined()
        if evasion_type == EVASION_BOTH_COMBINED:
            return dynamic_static_combined()


    # returns the the exploits list according to 'which_exploits'
    def exploits(self, which_exploits):
        if (which_exploits == EXPLOIT_ALL):
            return enumerate_exploits(EXPLOIT_ALL)
        else: # if a specific list of exploit(s) was given...
            if type(which_exploits) is str:
                return [which_exploits]
            if type(which_exploits) is list:
                return which_exploits


    # returns the the shellcodes list according to 'which_shellcodes'
    def shellcodes(self, which_shellcodes):
        if (which_shellcodes == SHELLCODE_ALL):
            return enumerate_shellcodes(SHELLCODE_ALL)
        else: # if a specific list of shellcode(s) was given...
            if type(which_shellcodes) is str:
                return [which_shellcodes]
            if type(which_shellcodes) is list:
                return which_shellcodes


    def effectiveness(self, analyzer, evasion_type, exps, shells):
        evasions = self.evasions(evasion_type)
        exploits = self.exploits(exps)
        shellcodes = self.shellcodes(shells)
        for evasion in evasions:
            #sys.stdout.write('.')
            sys.stdout.flush()
            for exploit in exploits:
                for shell in shellcodes:
                    # evasion vs. no evasion case
                    ev_exc_outcome = self.db.outcome(
                        exploit, shell, get_id(no_testcase()), analyzer)
                    ev_inc_outcome = self.db.outcome(
                        exploit, shell, get_id(evasion), analyzer)                     

                    # skip test cases that are not found in the DB
                    if (ev_exc_outcome == -1 or ev_inc_outcome == -1):
                        continue
                    
                    # compare detection outcome for the pair
                    result = self.compare_detections(
                        ev_exc_outcome,
                        ev_inc_outcome)
                    
                    self.store_eff_counter_eff(result, evasion, evasion_type)

                    # compute the added effectiveness in case the evasion is a combined one.
                    if (is_evasion_combined(evasion) and
                        ev_exc_outcome == 'malicious' and
                        ev_inc_outcome == 'non-malicious'):
                        has_no_added_eff = False
                        for constituent in constituents(evasion):
                            outcome = self.db.outcome(exploit, shell, get_id(constituent), analyzer)
                            if outcome == 'non-malicious' or outcome == -1: # if benign or not found...
                                has_no_added_eff = True
                                break
                        if has_no_added_eff:
                            self.has_added_eff(False, evasion, evasion_type)
                            continue # go to the next shellcode
                        # when none of the constituents are benign, the evasion has added eff.
                        self.has_added_eff(True, evasion, evasion_type)


    # TODO: distinguish between effectiveness equal to 0 and undefined effectiveness
    def mine_evasion_effectiveness(self, analyzers,
        evasions=EVASION_ALL,
        exploits=EXPLOIT_ALL,
        shellcodes=SHELLCODE_ALL,
        results_order="sorted",
        given_order="",
        csv_filename="output.csv"
        ):

        # create the keys in 'self.percentage_res' according to 'evasions' and set the values to 0
        self.initialize_percentage_res(evasions)

        if (type(analyzers) is str):
            analyzers = [analyzers]
        for analyzer in analyzers:
            print analyzer
            # count the number of times each evasion has 'worked', 'failed', or 'worsened'.
            if (evasions == EVASION_ALL or evasions == EVASION_ALL_DYNAMIC):
                self.effectiveness(analyzer, EVASION_DYNAMIC, exploits, shellcodes)
                self.effectiveness(analyzer, EVASION_DYNAMIC_COMBINED, exploits, shellcodes)
            if (evasions == EVASION_ALL or evasions == EVASION_ALL_STATIC):
                self.effectiveness(analyzer, EVASION_STATIC, exploits, shellcodes)
                self.effectiveness(analyzer, EVASION_STATIC_COMBINED, exploits, shellcodes)
            if (evasions == EVASION_ALL or evasions == EVASION_ALL_HYBRID):
                self.effectiveness(analyzer, EVASION_BOTH, exploits, shellcodes)
                self.effectiveness(analyzer, EVASION_BOTH_COMBINED, exploits, shellcodes)

            # convert the raw data (computed above) to the actual percentages that are reported in the paper.
            analyzer_res = self.result_to_ratio()

            # take average among all the analyzers
            for tc_id in analyzer_res:
                self.percentage_res[tc_id]['effectiveness'] += \
                    analyzer_res[tc_id]['effectiveness'] / len(analyzers)

                self.percentage_res[tc_id]['counter-effectiveness'] += \
                    analyzer_res[tc_id]['counter-effectiveness'] / len(analyzers)

            # DON'T FORGET TO RE-INIT THE RESULTS DICTIONARIES FOR THE NEXT ANALYZER!
            self.results = {}
            print ""

        if (results_order == "sorted"):
            self.sort_percentage_res_desc()
        elif (results_order == "given_order"):
            self.sort_percentage_res_by(given_order)

        self.write_to_csv(csv_filename)

        return self.percentage_res


    def added_effectiveness(self, analyzers,
        csv_filename="output.csv"
        ):

        overall_added_eff = {}
        percentage_res = {}
        added_eff = {}
        count = {} # for the base of each testcase (e.g. capthca,decoy), keeps how many times it has added eff

        if (type(analyzers) is str):
            analyzers = [analyzers]
        for analyzer in analyzers:
            print "Added effectiveness for {0}".format(analyzer)
            # mine added effectiveness
            self.effectiveness(analyzer, EVASION_DYNAMIC_COMBINED, EXPLOIT_ALL, SHELLCODE_ALL)
            self.effectiveness(analyzer, EVASION_STATIC_COMBINED, EXPLOIT_ALL, SHELLCODE_ALL)
            self.effectiveness(analyzer, EVASION_BOTH, EXPLOIT_ALL, SHELLCODE_ALL)
            self.effectiveness(analyzer, EVASION_BOTH_COMBINED, EXPLOIT_ALL, SHELLCODE_ALL)

            for tc_id in self.added_eff:
                # we're only interested to non-zero added effectiveness...
                if (self.added_eff[tc_id]['added_eff'] > 0 and 
                    self.results[tc_id]['evasion_worked'] > 0):
                        percentage_res[tc_id] = {}
                        percentage_res[tc_id]['added-effectiveness'] = round(float(
                            self.added_eff[tc_id]['added_eff']) / float(
                            self.results[tc_id]['evasion_worked']) * 100.0, 2)
                        
                        try:
                            tc_base = get_base_evasion(tc_id)
                            added_eff[tc_base] += percentage_res[tc_id]['added-effectiveness']
                            count[tc_base] += 1
                        except KeyError: # initialize a new entry...
                            added_eff[tc_base] = percentage_res[tc_id]['added-effectiveness']
                            count[tc_base] = 1

            for combined_evasion in added_eff:
                added_eff[combined_evasion] /= float(count[combined_evasion])
                try:
                    overall_added_eff[combined_evasion] += \
                        added_eff[combined_evasion] / float(len(analyzers))
                except KeyError:
                    overall_added_eff[combined_evasion] = \
                        added_eff[combined_evasion] / float(len(analyzers))

            # DON'T FORGET TO RE-INIT THE RESULTS DICTIONARIES FOR THE NEXT ANALYZER!
            percentage_res = {}
            self.added_eff = {}
            added_eff = {}
            count = {}
            print ""

        result = OrderedDict()
        for k, v in sorted(overall_added_eff.iteritems(), key=lambda (k,v): (v,k), reverse=True):
            result.update({k: v})

        output_file = open(csv_filename, "w")
        output_file.write("Evasion, Added effectiveness")
        output_file.write("\n")        
        for evasion in result:
            output_file.write("{0}, {1}".format(evasion, result[evasion]))
            output_file.write("\n")           
        output_file.close()

        return result


    # returns the actual effectiveness, counter-effectiveness, and added effectiveness
    # percentages that's reported in the paper
    def result_to_ratio(self):
        percentage_res = {}

        for tc_id in self.results:
            result = self.results[tc_id]
            percentage_res[tc_id] = {}
            percentage_res[tc_id]['type'] = result['evasion_type']

            # effectiveness
            try:
                percentage_res[tc_id]['effectiveness'] = round(float(result['evasion_worked']) / float(
                    result['evasion_worked'] + result['evasion_failed']) * 100.0, 2)
            except ZeroDivisionError:
                percentage_res[tc_id]['effectiveness'] = 0.00

            # counter-effectiveness
            try:
                percentage_res[tc_id]['counter-effectiveness'] = round(float(result['evasion_worsened']) / float(
                    result['evasion_worsened'] + result['evasion_neutral']) * 100.0, 2)
            except ZeroDivisionError:
                percentage_res[tc_id]['counter-effectiveness'] = 0.00
          
        return percentage_res


    def mine_vulnerability_to_single_evasions(self, analyzer):
        total_pairs_that_worked = 0
        worked = {}
        # initialize the 'worked' dictionary
        for evasion in single_evasion_testcases():
            worked[get_base_evasion(evasion)] = 0

        for evasion in single_evasion_testcases():
            for exploit in enumerate_exploits(EXPLOIT_ALL):
                for shell in enumerate_shellcodes(SHELLCODE_ALL):
                    # evasion vs. no evasion case
                    ev_exc_outcome = self.db.outcome(
                        exploit, shell, get_id(no_testcase()), analyzer)
                    ev_inc_outcome = self.db.outcome(
                        exploit, shell, get_id(evasion), analyzer)
                    # skip test cases that are not found in the DB
                    if (ev_exc_outcome == -1 or ev_inc_outcome == -1):
                        continue

                    # if the evasion has worked...
                    if (ev_exc_outcome == "malicious" and ev_inc_outcome == "non-malicious"):
                        worked[get_base_evasion(evasion)] += 1
                        total_pairs_that_worked += 1

        for evasion in worked:
            worked[evasion] = round(
                float(worked[evasion]) / float(total_pairs_that_worked) * 100.0,
                2
                )

        return worked


    # sorts the 'percentage_res' descendingly in the following order:
    # dynamic evasions first, then static evasions, finally hybrid evasions.
    # TODO: refactor to remove the duplication for each evasion type
    def sort_percentage_res_desc(self):
        result = OrderedDict()

        # static evasions
        temp = []
        for key in self.percentage_res:
            val = self.percentage_res[key]
            if (val['type'] == EVASION_STATIC or val['type'] == EVASION_STATIC_COMBINED):
                temp.append(
                    {'id': key,
                    'type': val['type'],
                    'eff': val['effectiveness'],
                    'counter-eff': val['counter-effectiveness'],
                    'added-eff': val['added-effectiveness']})
        sorted_temp = sorted(temp, key=operator.itemgetter('eff'), reverse=True)
        for item in sorted_temp:
            result.update(
                {item['id']: {
                    'type': item['type'],
                    'effectiveness': item['eff'],
                    'counter-effectiveness': item['counter-eff'],
                    'added-effectiveness': item['added-eff']
                }}
            )

        # dynamic evasions
        temp = []
        for key in self.percentage_res:
            val = self.percentage_res[key]
            if (val['type'] == EVASION_DYNAMIC or val['type'] == EVASION_DYNAMIC_COMBINED):
                temp.append(
                    {'id': key,
                    'type': val['type'],
                    'eff': val['effectiveness'],
                    'counter-eff': val['counter-effectiveness'],
                    'added-eff': val['added-effectiveness']})
        sorted_temp = sorted(temp, key=operator.itemgetter('eff'), reverse=True)
        for item in sorted_temp:
            result.update(
                {item['id']: {
                    'type': item['type'],
                    'effectiveness': item['eff'],
                    'counter-effectiveness': item['counter-eff'],
                    'added-effectiveness': item['added-eff']
                }}
            )

        # hybrid evasions
        temp = []
        for key in self.percentage_res:
            val = self.percentage_res[key]
            if (val['type'] == EVASION_BOTH or val['type'] == EVASION_BOTH_COMBINED):
                temp.append(
                    {'id': key,
                    'type': val['type'],
                    'eff': val['effectiveness'],
                    'counter-eff': val['counter-effectiveness'],
                    'added-eff': val['added-effectiveness']})
        sorted_temp = sorted(temp, key=operator.itemgetter('eff'), reverse=True)
        for item in sorted_temp:
            result.update(
                {item['id']: {
                    'type': item['type'],
                    'effectiveness': item['eff'],
                    'counter-effectiveness': item['counter-eff'],
                    'added-effectiveness': item['added-eff']
                }}
            )

        self.percentage_res = result


    def sort_percentage_res_by(self, given_order):
        temp = OrderedDict()

        for tc_id in given_order:
            temp.update(
                {tc_id: {'type': self.percentage_res[tc_id]['type'],
                        'effectiveness': self.percentage_res[tc_id]['effectiveness'],
                        'counter-effectiveness': self.percentage_res[tc_id]['counter-effectiveness'],
                        'added-effectiveness': self.percentage_res[tc_id]['added-effectiveness']}
                }
            )

        self.percentage_res = temp


    def write_to_csv(self, output_filename):
        output_file = open(output_filename, "w")
        
        output_file.write("Evasion, Type, Static Evasion, Dynamic Evasion, Hybrid Evasion")
        output_file.write("\n")
        
        for tc_id in self.percentage_res:
            result = self.percentage_res[tc_id]
            output_file.write("{0}, {1}, ".format(tc_id, result['type']))

            if (result['type'] == EVASION_STATIC or result['type'] == EVASION_STATIC_COMBINED):
                output_file.write("{0}, {1}, {2}".format(
                    result['effectiveness'], "", ""))

            if (result['type'] == EVASION_DYNAMIC or result['type'] == EVASION_DYNAMIC_COMBINED):
                output_file.write("{0}, {1}, {2}".format(
                    "", result['effectiveness'], ""))

            if (result['type'] == EVASION_BOTH or result['type'] == EVASION_BOTH_COMBINED):
                output_file.write("{0}, {1}, {2}".format(
                    "", "", result['effectiveness']))

            output_file.write("\n")
            
        output_file.close()



    # returns the average effectiveness over the evasions that 'percentage_res' was calculated based on
    @staticmethod
    def average(percentage_res):
        avg = 0.0
        testcases_count = len(percentage_res)

        for tc_id in percentage_res:
            avg += percentage_res[tc_id]['effectiveness'] / testcases_count

        return avg

    '''
    calculates the best case effectiveness for abstract evasions as follows:
    1. for arg-taking evasions, the average eff is taken per arg over all analyzers, shellcode, exploits
    then the max eff is taken over all args as for the best case eff
    2. for non-arg-taking evasions, the average eff is taken over all analyzers, shellcode, exploits
    the number yielded above would be the best case eff
    '''
    @staticmethod
    def best_case_effectiveness(percentage_res):
        best_eff = {}

        for testcase in single_evasion_testcases():
            try:
                base_evasion = get_base_evasion(testcase)
                tc_id = get_id(testcase)
                best_eff[base_evasion] = max(
                    percentage_res[tc_id]['effectiveness'],
                    best_eff[base_evasion]
                )
            except KeyError: # happens when 'base_evasion' is not found...
                try:
                    # initialize a new entry
                    best_eff[base_evasion] = percentage_res[tc_id]['effectiveness']
                except KeyError: # happens when 'tc_id' is not found...
                    pass # skip

        return best_eff

    '''
    calculates the worst case counter-effectiveness for abstract evasions as follows:
    1. for arg-taking evasions, the average counter-eff is taken per arg over all analyzers, shellcode, exploits
    then the max counter-eff is taken over all args as for the worst case counter-eff
    2. for non-arg-taking evasions, the average counter-eff is taken over all analyzers, shellcode, exploits
    the number yielded above would be the worst case counter-eff
    '''
    @staticmethod
    def worst_case_counter_effectiveness(percentage_res):
        worst_counter_eff = {}

        for testcase in single_evasion_testcases():
            try:
                base_evasion = get_base_evasion(testcase)
                tc_id = get_id(testcase)
                worst_counter_eff[base_evasion] = max(
                    percentage_res[tc_id]['counter-effectiveness'],
                    worst_counter_eff[base_evasion]
                )
            except KeyError: # happens when 'base_evasion' is not found...
                try:
                    # initialize a new entry
                    worst_counter_eff[base_evasion] = percentage_res[tc_id]['counter-effectiveness']
                except KeyError: # happens when 'tc_id' is not found...
                    pass # skip

        return worst_counter_eff

