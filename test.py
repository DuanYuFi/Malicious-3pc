strs = '''Arith part in SpdzWiseRing: 
Total check comm: 7707232

Arith part in Replicated: 
Total multiplies: 519532
Exchange comm: 9351576

Arith part in Replicated: 
Total multiplies: 524576
Exchange comm: 6819488

Arith part in Replicated: 
Total multiplies: 2522
Total dotprod: 5044
Exchange comm: 98358

Arith part in Replicated: 
Total multiplies: 43787369
Exchange comm: 569235797

Arith part in SpdzWiseRing: 
Total check comm: 152800

Arith part in Replicated: 
Total multiplies: 10300
Exchange comm: 185400

Arith part in Replicated: 
Total multiplies: 10400
Exchange comm: 135200

Arith part in Replicated: 
Total multiplies: 9008092
Total dotprod: 1001
Exchange comm: 117118209

Arith part in Replicated: 
Total multiplies: 9010144
Total dotprod: 1101
Exchange comm: 117146185

Binary part: 
Total and gates: 16188615
Check comm: 2516000
Exchange comm: 129504125

Arith part in SpdzWiseRing: 
Total check comm: 2759568

Arith part in Replicated: 
Total multiplies: 186018
Exchange comm: 3348324

Arith part in Replicated: 
Total multiplies: 187824
Exchange comm: 2441712

Arith part in Replicated: 
Total multiplies: 9020000
Total dotprod: 902
Exchange comm: 117271726

Arith part in Replicated: 
Total multiplies: 9020903
Total dotprod: 2708
Exchange comm: 117306943

Arith part in SpdzWiseRing: 
Total check comm: 1949728

Arith part in Replicated: 
Total multiplies: 131428
Exchange comm: 2365704

Arith part in Replicated: 
Total multiplies: 132704
Exchange comm: 1725152

Arith part in Replicated: 
Total multiplies: 638
Total dotprod: 1276
Exchange comm: 24882

Arith part in Replicated: 
Total multiplies: 12760000
Exchange comm: 165880000

Arith part in SpdzWiseRing: 
Total check comm: 293376

Arith part in Replicated: 
Total multiplies: 19776
Exchange comm: 355968

Arith part in Replicated: 
Total multiplies: 19968
Exchange comm: 259584

Arith part in Replicated: 
Total multiplies: 660480
Total dotprod: 694624
Exchange comm: 17616352

Arith part in Replicated: 
Total multiplies: 3170080
Total dotprod: 694816
Exchange comm: 50243648

Binary part: 
Total and gates: 3233215
Check comm: 503200
Exchange comm: 25753845

Arith part in SpdzWiseRing: 
Total check comm: 1952784

Arith part in Replicated: 
Total multiplies: 131634
Exchange comm: 2369412

Arith part in Replicated: 
Total multiplies: 132912
Exchange comm: 1727856

Arith part in Replicated: 
Total multiplies: 6380000
Total dotprod: 638
Exchange comm: 82948294

Arith part in Replicated: 
Total multiplies: 6380639
Total dotprod: 1916
Exchange comm: 82973215

Significant amount of unused bits of SPDZ-wise replicated Z2^104. For more accurate benchmarks, consider reducing the batch size with -b.
Arith part in SpdzWiseRing: 
Total check comm: 1949728

Arith part in Replicated: 
Total multiplies: 131428
Exchange comm: 2365704

Arith part in Replicated: 
Total multiplies: 132704
Exchange comm: 1725152

Arith part in Replicated: 
Total multiplies: 638
Total dotprod: 1276
Exchange comm: 24882
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