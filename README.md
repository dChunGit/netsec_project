# netsec_project

1. Navigate to /code/networkscanner
2. Install requirements
3. Start p0f with log.txt as the output file command line arg. The command line is "p0f -i \<interface\> -o log.txt"
4. Run networkscanner.py
5. When the enter prompt appears in networkscanner, stop the p0f scan.
6. Copy candidates.csv over to ../deepscanner
7. Navigate to ../deepscanner
8. Run test_candidates.py
9. See results in results.csv

BlueKeep scanner used in test_candidates.py from: https://github.com/turingcompl33t/bluekeep
