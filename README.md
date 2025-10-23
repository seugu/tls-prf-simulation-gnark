# tls-prf-simulation-gnark
This repo simulates the TLS-PRF in TLS1.2 HMAC in gnark with 60 SHA256 compression

simulates the similar work for tls-prf with 60 compressions resulted in 4.7 seconds. 

```
22:11:42 INF compiling circuit
22:11:42 INF parsed circuit inputs nbPublic=33 nbSecret=3831
22:11:51 INF building constraint builder nbConstraints=1719598
22:14:24 DBG constraint system solver done nbConstraints=1719598 took=1127.892625
22:14:29 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=1719598 took=4723.446875
22:14:29 DBG verifier done backend=groth16 curve=bn254 took=2.213958
Verify error: <nil>
```
