Go ABE
============

This is a simple experiment in Attribute Based Encryption.

- It is based entirely on sha256 hashes
- Requires the CA to both assert attributes, and sign policy  
- Does not prevent collusion yet

The basic idea is to take a large random number representing a key,
and to blind it by subtracting a large number from it.  Whoever
has access can calculate what to add back in.

```
   or has email admin@crypto.org
   and
     has age adult
     has citizenship US UK
```

We want to be able to calculate a key `k` when the user can satisfy
a boolean predicate with attested attributes that come from a
certificate of these attributes:

```
alice = {
  (has age adult) -> proof( has age adult ),
  (has citizenship UK) -> proof( has citizenship UK)
}
```

When plugged into the access policy ( a boolean circuit ), 
it should yield the key.  The basic idea is that an access policy has possible cases where it can match.

- (has email admin@crypto.org)
- (has age adult) and (has citizenship US)
- (has age adult) and (has citizenship UK)

Each of these cases can correspond to a value that can be added to to yield the key.  Only the rightful owner of these attributes can calculate what to add to it.  The cases store:

- `key - Hash[fileId + proofHasEmailAdmin]`
- `key - Hash[fileId + proofAgeAdult + proofCitizenshipUS]`
- `key - Hash[fileId + proofAgeAdult + proofCitizenshipUK]`

If we hash the has conditions, we can obscure what the name and value are for these.  The policy has a map of these hashes so that the user can figure out which expressions can be matched.  A proof is a MAC of the has condition.  The certificate has these proofs, as this is the point of the certificate.

The service trying to create a policy does not have these proofs.  But he can defer to the CA to create them.

When the user wants to unwrap a crypto key, it is as simple as calculating what to add back in....

- `Hash[fileId + proofHasEmailAdmin]`
- `Hash[fileId + proofAgeAdult + proofCitizenshipUS]`
- `Hash[fileId + proofAgeAdult + proofCitizenshipUK]`

This allows the key to be recovered for all the various cases.

Problem
============

The problem I am not trying to solve right now is that of collusion.  People can put their certificates together, and get proofs such as `(has citizenship US)` to satisfy predicates that they cannot satisfy alone.  There needs to be more imaginitive cryptography primitives to fix this problem (probably Elliptic Curve Pairings).  The idea is to watermark all of the attributes so that all attributes used in the expression have to come from the same certificate in order to calculate the key.
