'''
database access layer for the higher layers.
IMPORTANT HINT: This class is not thread-safe!
It's the responsibility of the user of this class to take care of thread safety.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''

import pymysql.cursors
from warnings import filterwarnings
filterwarnings('ignore', category = pymysql.Warning)

class DataBase:

    def __enter__(self):
        return self

    def __exit__(self, type, val, trace):
        self.connection.commit()
        self.cursor.close()
        self.connection.close()

    def __init__(self, clean_db="no"):
        self.connection = pymysql.connect(
            host='localhost', user='chameleon', password='', db='chameleon')
        self.cursor = self.connection.cursor()
        self.cursor.execute("create database if not exists chameleon")
        if (clean_db == "yes" or clean_db == "y" or clean_db == "true"):
            self.cursor.execute("drop table if exists observed_signals")
            self.cursor.execute("drop table if exists results")
            self.cursor.execute("drop table if exists evasions")
            self.cursor.execute("drop table if exists signals")
            self.cursor.execute("drop table if exists samples")
        self.cursor.execute("create table if not exists samples(\
            sample_id mediumint not null auto_increment,\
            testcase_id char(255) not null,\
            filename char(150) not null,\
            creation_date char (20) not null, \
            module_name char(50) not null,\
            shellcode char(30),\
            exploit char(30),\
            expected_outcome char (30),\
            sha256 char(70),\
            sha1 char(50),\
            md5 char(40),\
            primary key(sample_id)\
            )")
        self.cursor.execute("create table if not exists evasions(\
            evasion_id mediumint not null auto_increment,\
            sample_id mediumint not null,\
            name char(150) not null,\
            primary key(evasion_id),\
            foreign key (sample_id) references samples(sample_id)\
            )")
        self.cursor.execute("create table if not exists signals(\
            signal_id mediumint not null auto_increment,\
            sample_id mediumint not null,\
            name char(50) not null,\
            primary key(signal_id),\
            foreign key (sample_id) references samples(sample_id)\
            )")
        self.cursor.execute("create table if not exists results(\
            result_id mediumint not null auto_increment,\
            sample_id mediumint not null,\
            analyzer_name char(50),\
            analyzer_version char(50),\
            vendor_analysis_id char(100),\
            analysis_datetime char(20),\
            windows_version char(20),\
            adobe_version char(20),\
            observed_outcome char(30),\
            observed_outcome_comment char(200),\
            primary key(result_id),\
            foreign key (sample_id) references samples(sample_id)\
            )")
        self.cursor.execute("create table if not exists observed_signals(\
            signal_id mediumint not null auto_increment,\
            result_id mediumint not null,\
            name char(50) not null,\
            primary key(signal_id),\
            foreign key (result_id) references results(result_id)\
            )")

    def store_sample(self, testcase_id, filename, exploit, shell, evasion_arr, signals, outcome):
        if (evasion_arr == []):
            evasion_arr = [["none"]]
        # in the DB there is a legacy column called 'exploit', which is hard-coded to "yes" in the following
        self.cursor.execute("insert into samples (testcase_id, filename, creation_date, \
            module_name, shellcode, exploit, expected_outcome) values\
            ('%s', '%s', %s, '%s', '%s', '%s', '%s')" % \
            (testcase_id, filename, "curdate()", exploit, shell, "yes", outcome))
        self.connection.commit()
        sample_id = self.cursor.lastrowid
        for ev in evasion_arr:
            self.cursor.execute(
                "insert into evasions (sample_id, name) values (%s, '%s')" % (sample_id, ",".join(ev)))
            self.connection.commit()
        for signal in signals:
            self.cursor.execute(
                "insert into signals (sample_id, name) values (%s, '%s')" % (sample_id, signal))
            self.connection.commit()

    def store_sample_hash(self, filename, sha256, sha1, md5):
        self.cursor.execute("update samples set sha256 = '%s', sha1 = '%s', md5 = '%s' where filename = '%s'" % \
            (sha256, sha1, md5, filename))
        self.connection.commit()

    """
    'result' should be a dictionary with the following keys (all can be null):
    'analyzer_name'
    'analyzer_version'
    'vendor_analysis_id'
    'analysis_datetime'
    'windows_version'
    'adobe_version'
    'observed_signals': comma-separated list of observed_signals
    'observed_outcome'
    'observed_outcome_comment': for static analyzers that report the signature of the sample (e.g. exploit-cve-1234).
    """
    def store_result(self, sample_sha256, result):
        # get the most recently generated sample (max(sample_id)) in case there are more than one match.
        self.cursor.execute("select max(sample_id) from samples where sha256 = '%s'" % sample_sha256)
        sample_id = self.cursor.fetchone()[0] # 0 is SAMPLE_ID_COLUMN_INDEX
        if (sample_id == None):
            return -1 # no result
        # if the exact same results was already stored...
        self.cursor.execute("select * from results where sample_id = %s and \
            analyzer_name = '%s' and analyzer_version = '%s' and vendor_analysis_id = '%s' and \
            analysis_datetime = '%s' and windows_version = '%s' and adobe_version = '%s' and \
            observed_outcome = '%s' and observed_outcome_comment = '%s'" % \
            (sample_id, result['analyzer_name'], result['analyzer_version'],
                result['vendor_analysis_id'], result['analysis_datetime'], result['windows_version'],
                result['adobe_version'], result['observed_outcome'], result['observed_outcome_comment']))
        if self.cursor.rowcount > 0:
            return 0 # skip re-storing the exact same result!
        self.cursor.execute("insert into results (sample_id, analyzer_name, analyzer_version, \
            vendor_analysis_id, analysis_datetime, windows_version, adobe_version, \
            observed_outcome, observed_outcome_comment) values \
            (%s, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
            (sample_id, result['analyzer_name'], result['analyzer_version'], result['vendor_analysis_id'],
                result['analysis_datetime'], result['windows_version'], result['adobe_version'],
                result['observed_outcome'], result['observed_outcome_comment']))
        self.connection.commit()
        result_id = self.cursor.lastrowid
        for signal in result['observed_signals'].split(","):
            self.cursor.execute("insert into observed_signals (result_id, name) values (%s, '%s')" % (result_id, signal))
            self.connection.commit()
        return 0

    def outcome(self, exploit, shell, testcase_id, analyzer):
        # in case more than one entries match the query, the most recently scanned should be retunred.
        # that's why in the following we get the maximum on result_id.
        query = "\
        select observed_outcome \
        from results \
        where result_id in \
        ( \
        select max(r.result_id) \
        from samples s inner join results r \
        on s.sample_id = r.sample_id \
        where r.analyzer_name = '%s' \
        and s.module_name = '%s' \
        and s.shellcode = '%s' \
        and s.testcase_id = '%s' \
        ) \
        "

        if (self.cursor.execute(query % (analyzer, exploit, shell, testcase_id)) <= 0):
            return -1 # sample not found
        else:
            return self.cursor.fetchone()[0]

    # observed_outcome="" means the analyzer's outcome doesn't matter for the count
    def total_outcome_count(self, analyzer, expected_outcome, observed_outcome=""):
        if (observed_outcome == ""):
            query = "\
            select count(*) from \
            samples s inner join results r \
            on s.sample_id = r.sample_id \
            where r.analyzer_name = '%s' \
            and s.expected_outcome = '%s' \
            "

            if (self.cursor.execute(query % (
                analyzer, expected_outcome)) <= 0):
                return -1 # entry not found in the DB
            else:
                return self.cursor.fetchone()[0]
        else:
            query = "\
            select count(*) from \
            samples s inner join results r \
            on s.sample_id = r.sample_id \
            where r.analyzer_name = '%s' \
            and s.expected_outcome = '%s' \
            and r.observed_outcome = '%s' \
            "

            if (self.cursor.execute(query % (
                analyzer, expected_outcome, observed_outcome)) <= 0):
                return -1 # entry not found in the DB
            else:
                return self.cursor.fetchone()[0]

    def total_outcome_count_per_exploit(self, analyzer, exploit, expected_outcome):
        query = "\
        select count(*) from \
        samples s inner join results r \
        on s.sample_id = r.sample_id \
        where r.analyzer_name = '%s' \
        and s.module_name = '%s' \
        and s.expected_outcome = '%s' \
        "

        if (self.cursor.execute(query % (
            analyzer, exploit, expected_outcome)) <= 0):
            return -1 # entry not found in the DB
        else:
            return self.cursor.fetchone()[0]

    def hash_filename_for(self, testcase_id, exp, shell, analyzer):
        query = "\
        select s.sha256, s.filename from \
        samples s inner join results r \
        on s.sample_id = r.sample_id \
        where r.analyzer_name = '%s' \
        and s.testcase_id = '%s' \
        and s.module_name = '%s' \
        and s.shellcode = '%s' \
        "

        if (self.cursor.execute(query % (
            analyzer, testcase_id, exp, shell)) <= 0):
            return -1 # entry not found in the DB
        else:
            return self.cursor.fetchone()




