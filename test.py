strs = '''In Replicated at ring 2Z2ILi64EE: 
Number of replicated Z2^64 multiplications: 18016184 (-9009093 bits) in 60 rounds
Number of replicated Z2^64 dot products: 1001
Bytes of communication in exchange: 72072744

In Replicated at ring 7BitVec_IlE: 
Number of replicated secret multiplications: 16188615 (1036028235 bits) in 420 rounds
Bytes of communication in exchange: 129504125

In Replicated at ring 2Z2ILi64EE: 
Number of replicated Z2^64 multiplications: 9020000 (-9020000 bits) in 902 rounds
Bytes of communication in exchange: 72160000

In Replicated at ring 2Z2ILi64EE: 
Number of replicated Z2^64 multiplications: 21228544 (-21728256 bits) in 33952 rounds
Number of replicated Z2^64 dot products: 11113984
Bytes of communication in exchange: 173826048

In Replicated at ring 7BitVec_IlE: 
Number of replicated secret multiplications: 51835910 (3303654400 bits) in 52115 rounds
Bytes of communication in exchange: 412962535

In Replicated at ring 2Z2ILi64EE: 
Number of replicated Z2^64 multiplications: 102220000 (-102220000 bits) in 10222 rounds
Bytes of communication in exchange: 817760000
'''

lines = strs.split('\n')

total_comm = 0

for line in lines:
    if line.startswith("Bytes of communication in exchange: "):
        total_comm += int(line.split(': ')[1])

print(total_comm / 1024 / 1024)