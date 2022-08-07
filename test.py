strs = '''Total and gates: 16188615
Check comm: 2516000
Exchange comm: 129504125
Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Total and gates: 3256155
Check comm: 505920
Exchange comm: 25937365

Total and gates: 3256155
Check comm: 505920
Exchange comm: 25937365

Total and gates: 3256155
Check comm: 505920
Exchange comm: 25937365

Total and gates: 3277235
Check comm: 510000
Exchange comm: 26106005
'''

total_and_gates = 0
check_comm = 0
and_comm = 0

lines = strs.split('\n')
for line in lines:
    if line.startswith("Total and gates: "):
        total_and_gates += int(line.split(': ')[1])
    elif line.startswith("Check comm: "):
        check_comm += int(line.split(': ')[1])
    elif line.startswith("Exchange comm: "):
        and_comm += int(line.split(': ')[1])

print("Total and gates: {}".format(total_and_gates))
print("Check comm: {}".format(check_comm))
print("Exchange comm: {}".format(and_comm))