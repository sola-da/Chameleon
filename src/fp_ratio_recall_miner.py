'''
computes false positive ratio and recall for the given analyzers.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''

from db import DataBase

class FPRatioRecallMiner:
    
    def __init__(self):
        self.db = DataBase()
        self.results = {}

    def mine_fp_ratio_recall_for(self, analyzer):
        self.results[analyzer] = {}

        false_pos = float(self.db.total_outcome_count(
            analyzer, 'non-malicious', 'malicious'))
        total_neg = float(self.db.total_outcome_count(
            analyzer, 'non-malicious'))
        self.results[analyzer]['fp_ratio'] = round(
            false_pos / total_neg * 100.0, 2)


        true_neg = float(self.db.total_outcome_count(
            analyzer, 'malicious', 'malicious'))
        total_pos = float(self.db.total_outcome_count(
            analyzer, 'malicious'))
        self.results[analyzer]['recall'] = round(
            true_neg / total_pos * 100.0, 2)
        


    def mine_for_analyzers(
        self,
        analyzers,
        csv_filename="fp_ratio_recall.csv"):

        for analyzer in analyzers:
            self.mine_fp_ratio_recall_for(analyzer)

        self.write_to_csv(csv_filename)

        return self.results



    def write_to_csv(self, output_filename):
        output_file = open(output_filename, "w")
        output_file.write("Analyzer, FP Ratio, Recall")
        for analyzer in self.results:
            result = self.results[analyzer]
            output_file.write("\n")
            output_file.write("{0}, {1}, {2}".format(
                analyzer, result['fp_ratio'], result['recall']))
        output_file.close()
