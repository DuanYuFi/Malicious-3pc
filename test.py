strs = '''Arith part in SpdzWiseRing: 
Total check comm: 36672

Arith part in Replicated: 
Value type: 2Z2ILi144EE
Total multiplies: 2472
Exchange comm: 44496

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 2496
Exchange comm: 32448

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 36
Total dotprod: 24
Exchange comm: 468

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 49747369
Exchange comm: 646715797

Arith part in SpdzWiseRing: 
Total check comm: 9168

Arith part in Replicated: 
Value type: 2Z2ILi144EE
Total multiplies: 618
Exchange comm: 11124

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 624
Exchange comm: 8112

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 9009093
Total dotprod: 1001
Exchange comm: 117118209

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 9011104
Total dotprod: 1007
Exchange comm: 117144352

Binary part: 
Value type: 7BitVec_IlE
Total and gates: 16188615
Check comm: 12768
Exchange comm: 129504125
Bit counter: 1036028235
Total rounds: 420

Arith part in SpdzWiseRing: 
Total check comm: 15280

Arith part in Replicated: 
Value type: 2Z2ILi144EE
Total multiplies: 1030
Exchange comm: 18540

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 1040
Exchange comm: 13520

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 12000004
Total dotprod: 4
Exchange comm: 156000052

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 12000019
Total dotprod: 14
Exchange comm: 156000247

Significant amount of unused bits of SPDZ-wise replicated Z2^104. For more accurate benchmarks, consider reducing the batch size with -b.
Arith part in SpdzWiseRing: 
Total check comm: 106960

Arith part in Replicated: 
Value type: 2Z2ILi144EE
Total multiplies: 7210
Exchange comm: 129780

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 7280
Exchange comm: 94640

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 105
Total dotprod: 70
Exchange comm: 1365

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 210000000
Exchange comm: -1564967296

Arith part in SpdzWiseRing: 
Total check comm: 24448

Arith part in Replicated: 
Value type: 2Z2ILi144EE
Total multiplies: 1648
Exchange comm: 29664

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 1664
Exchange comm: 21632

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 21728256
Total dotprod: 11113984
Exchange comm: 282467328

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 61973528
Total dotprod: 11114000
Exchange comm: 805655864

Binary part: 
Value type: 7BitVec_IlE
Total and gates: 51835910
Check comm: 38048
Exchange comm: 412962535
Bit counter: -991312896
Total rounds: 52115

Arith part in SpdzWiseRing: 
Total check comm: 110016

Arith part in Replicated: 
Value type: 2Z2ILi144EE
Total multiplies: 7416
Exchange comm: 133488

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 7488
Exchange comm: 97344

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 105000035
Total dotprod: 35
Exchange comm: 1365000455

Arith part in Replicated: 
Value type: 2Z2ILi104EE
Total multiplies: 105000143
Total dotprod: 107
Exchange comm: 1365001859
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