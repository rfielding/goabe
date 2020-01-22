package main

import "crypto/sha256"
import "fmt"
import "encoding/hex"
import "crypto/rand"
import "log"

//import "encoding/json"
import "bytes"

// sha256[ c Condition ]
type ConditionHash []byte

func (h ConditionHash) MarshalJSON() (string, error) {
	return hex.EncodeToString(h), nil
}

func (h ConditionHash) String() string {
	s, _ := h.MarshalJSON()
	return s
}

// have k hmac h
func (c ConditionHash) Approve(k PrivKey) ConditionProof {
	h := sha256.New()
	h.Write(k)
	h.Write(c)
	h.Write(k)
	v := h.Sum(nil)
	return ConditionProof(v[:])
}

var one = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1,
}

func byteNeg(a []byte) []byte {
	// flip all bits
	c := make([]byte, 32)
	for i := 31; i >= 0; i-- {
		c[i] = ^a[i]
	}
	// add one
	return byteAdd(c, one)
}

func byteAdd(a []byte, b []byte) []byte {
	c := make([]byte, 32)
	carry := int(0)
	for i := 31; i >= 0; i-- {
		v := (int(a[i]) + int(b[i]) + carry) % 256
		carry = (int(a[i]) + int(b[i])) / 256
		c[i] = byte(v)
	}
	return c
}

func byteSub(a []byte, b []byte) []byte {
	return byteAdd(a, byteNeg(b))
}

// sha256[ ch ConditionHash, caPrivate ]
type ConditionProof []byte

func (h ConditionProof) MarshalJSON() (string, error) {
	return hex.EncodeToString(h), nil
}

func (h ConditionProof) String() string {
	s, _ := h.MarshalJSON()
	return s
}

type PrivKey []byte

func NewPrivKey() PrivKey {
	v := make([]byte, 32)
	_, err := rand.Read(v)
	if err != nil {
		log.Printf("error reading random: %v", err)
		return nil
	}
	return PrivKey(v)
}

func (p PrivKey) MarshalJSON() (string, error) {
	return hex.EncodeToString(p), nil
}

func (h PrivKey) String() string {
	s, _ := h.MarshalJSON()
	return s
}

func (p PrivKey) PubKey() PubKey {
	v := sha256.Sum256(p)
	return PubKey(v[:])
}

type PubKey []byte

func (p PubKey) MarshalJSON() (string, error) {
	return hex.EncodeToString(p), nil
}

func (h PubKey) String() string {
	s, _ := h.MarshalJSON()
	return s
}

// a condition that we would like to assert
type Condition struct {
	Name  string
	Value string
}

// hash the condition so that everyone has the same value
func (c *Condition) Hash() ConditionHash {
	v := sha256.Sum256([]byte(fmt.Sprintf("%s: %s", c.Name, c.Value)))
	return ConditionHash(v[:])
}

type KeyPair struct {
	Pub  PubKey
	Priv PrivKey
}

type Certificate map[Condition]ConditionProof

type PolicyCase struct {
	// threshold condition
	Required []ConditionHash
	// key minus hash of condition proofs
	Target PrivKey
}

type Policy struct {
	Pub PubKey
	// possible cases that match
	Cases []PolicyCase
}

// give the ca the policyprivate key, so that it can calculate
// the proofs
func NewPolicy(capriv PrivKey, policypriv PrivKey, cases []PolicyCase) Policy {
	p := Policy{
		Pub:   policypriv.PubKey(),
		Cases: cases,
	}
	for i := range cases {
		// on a case, calculate:
		// target = policyPriv - H[ policypub + proofa0 + proofa1 + ...]
		total := make([]byte, 32)
		total = byteAdd(total, p.Pub)
		//log.Printf("newpolicy init %s", PrivKey(total))
		c := cases[i]
		for j := range c.Required {
			a := c.Required[j]
			proof := []byte(a.Approve(capriv))
			total = byteAdd(total, proof)
			//log.Printf("newpolicy %d %d: %s",i,j,PrivKey(proof))
		}
		v := sha256.Sum256(total)
		cases[i].Target = byteSub(policypriv, v[:]) //byteSub([]byte(policypriv), v[:])
	}
	return p
}

// neither policyPriv or caPriv are required
func UnlockPolicy(cert Certificate, policy Policy) PrivKey {
	for c := range policy.Cases {
		// on a case, calculate:
		// policyPriv = target + H[ policypub + proofa0 + proofa1 + ...]
		policyCase := policy.Cases[c]
		hasAll := true
		total := make([]byte, 32)
		total = byteAdd(total, policy.Pub)
		//log.Printf("unlock init %s", PrivKey(total))
		for r := range policyCase.Required {
			required := policyCase.Required[r]
			foundIt := false
			for a := range cert {
				if bytes.Compare(a.Hash(), required) == 0 {
					foundIt = true
					// add in proof of a
					total = byteAdd(total, cert[a])
					//log.Printf("unlock %d %d %s", c, r, PrivKey(cert[a]))
				}
			}
			if foundIt == false {
				hasAll = false
			}
		}
		if hasAll {
			v := sha256.Sum256(total)
			return PrivKey(byteAdd(policyCase.Target, v[:]))
		}
	}
	return nil
}

func main() {
	isEmailAdmin := Condition{Name: "email", Value: "admin@foo.com"}
	isEmailAdminHash := isEmailAdmin.Hash()

	isAgeAdult := Condition{Name: "age", Value: "adult"}
	isAgeAdultHash := isAgeAdult.Hash()

	isCitizenUS := Condition{Name: "citizen", Value: "US"}
	isCitizenUSHash := isCitizenUS.Hash()

	isCitizenUK := Condition{Name: "citizen", Value: "UK"}
	isCitizenUKHash := isCitizenUK.Hash()

	isCitizenNL := Condition{Name: "citizen", Value: "NL"}
	//isCitizenNLHash := isCitizenNL.Hash()

	capriv := NewPrivKey()
	//capub := capriv.PubKey()

	alice := Certificate{
		isAgeAdult:  isAgeAdult.Hash().Approve(capriv),
		isCitizenUK: isCitizenUK.Hash().Approve(capriv),
	}

	bob := Certificate{
		isAgeAdult:  isAgeAdult.Hash().Approve(capriv),
		isCitizenNL: isCitizenNL.Hash().Approve(capriv),
	}

	charles := Certificate{
		isAgeAdult:  isAgeAdult.Hash().Approve(capriv),
		isCitizenUS: isCitizenUS.Hash().Approve(capriv),
	}

	dave := Certificate{
		isEmailAdmin: isEmailAdmin.Hash().Approve(capriv),
	}

	// (and (has age adult) (or (has citizenship US) (has citizenship UK)))
	policyPriv := NewPrivKey()
	policy := NewPolicy(
		capriv,
		policyPriv,
		[]PolicyCase{
			PolicyCase{
				Required: []ConditionHash{isAgeAdultHash, isCitizenUKHash},
			},
			PolicyCase{
				Required: []ConditionHash{isAgeAdultHash, isCitizenUSHash},
			},
			PolicyCase{
				Required: []ConditionHash{isEmailAdminHash},
			},
		},
	)
	_ = policyPriv

	log.Printf("expect: %s", policyPriv)
	log.Printf("alice unlock: %s", UnlockPolicy(alice, policy))
	log.Printf("bob unlock: %s", UnlockPolicy(bob, policy))
	log.Printf("charles unlock: %s", UnlockPolicy(charles, policy))
	log.Printf("dave unlock: %s", UnlockPolicy(dave, policy))
}
