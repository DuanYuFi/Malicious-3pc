strs = '''In SpdzWiseRing zero_check
Arith part in SpdzWiseRing: 
Total check comm: 3056

Arith part in Replicated: 
Total multiplies: 206
Exchange comm: 3708

Arith part in Replicated: 
Total multiplies: 208
Exchange comm: 2704

Arith part in Replicated: 
Total multiplies: 1000000
Exchange comm: 13000000

Arith part in Replicated: 
Total multiplies: 1000001
Total dotprod: 2
Exchange comm: 13000039

Binary part: 
Total and gates: 1000000
Check comm: 156400
Exchange comm: 1000000
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