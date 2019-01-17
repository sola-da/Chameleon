# Chameleon

Chameleon, a framework for testing the anti-evasion capabilities of PDF malware scanners, runs in four independent steps as shown in the figure below. This repository contains the code base for steps Generate and Assess.

![chameleon_framework_overview](https://github.com/sola-da/Chameleon/blob/master/.images/overview.png "Overview of the Chameleon framework and its four steps")

Moreover, the set of 1395 malicious and evasive PDF files that is used in our study is available. The set can be used to benchmark a malware scanner in its anti-evasion abilities. Email Saeed Ehteshamifar (salpha.2004@gmail.com) if you're interested in obtaining the set. 


## Usage

**Prerequisites**

The following packages are needed to use the framework.

Linux/macOS packages:
- mysql-server (>= 10.1.26)
- metasploit-framework (>= 4.16.7)
- ruby (>= 2.3.3)
- pip (>= 9.0.1)
- bundler (>= 1.15.1)

Python packages (`pip install`):
- PyMySQL (>= 0.7.11)
- pytz (>= 2018.9)



### Generate
1. Edit `Gemfile` in Metasploit's installation directory (probably `/usr/share/metasploit-framework` or `/opt/metasploit-framework/embedded/framework`) and add an entry for Origami-PDF and Chunky PNG:
```text
gem 'origami'
gem 'chunky_png'
```
2. Run Bundler in the same directory to install the newly required Gem:
```sh
metasploit-framework# bundle
```
3. Clone this repository, go its directory, and copy the content of `metasploit_modules` directory to `msf4`:
```sh
Chameleon# cp -r ./src/metasploit_modules/* ~/.msf4
```
4. In Chameleon `src` directory, run `generator.py` to generate the test suite.
```sh
src# ./generator.py
```
Edit `testcases.py` to control which payloads, exploits, and evasions are used in the generation process.


### Assess
1. Scan a test suite with an analyzer and write the results to the database with the scheme defined in `database-scheme.txt`.
2. Implement the functions in `analyzers_list.py` according to the comments above the file and the analyzers used in the previous step.
3. Run `results_parser.py`:
```sh
src# ./results_parser.py
```

