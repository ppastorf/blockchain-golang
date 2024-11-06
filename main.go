package main

import (
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
    "encoding/hex"
	"fmt"
	"time"
)

func CalcHash(s string) string {
	// return CalcSha256(s)
	return CalcKeccak256(s)
}

func CalcKeccak256(dataS string) string {
    data := []byte(dataS)
    hasher := sha3.NewLegacyKeccak256()
    hasher.Write(data)
    hash := hasher.Sum(nil)
	return hex.EncodeToString(hash)
}

func CalcSha256(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	hashedData := hash.Sum(nil)
	hashedString := hex.EncodeToString(hashedData)
	return hashedString
}

func PrintHash(hash *string) string {
	if hash == nil {
		return fmt.Sprintf("nil")
	} else {
		return *hash
	}
}

// type HashT string

type User string

type Message interface {
	AsString() string
	Hash() string
}

type GenericMessage struct {
	Val string
}

func (m *GenericMessage) AsString() string {
	return fmt.Sprintf("%s", m.Val)
}

func (m *GenericMessage) Hash() string {
	return CalcHash(fmt.Sprintf("%s%s", m.Val))
}

type Transaction struct {
	Sender User
	Msg    Message
}

func (t *Transaction) Hash() string {
	data := fmt.Sprintf(
		"%s%s",
		t.Sender, t.Msg.Hash(),
	)
	return CalcHash(data)
}

type TCollection []Transaction

type Block struct {
	Index     int
	Proposer  string
	Timestamp time.Time
	Data      TCollection
	DataHash  *string
	PrevHash  *string
	Hash      *string
}

func (b *Block) CalcHash() {
	bHash := BlockHash(b)
	b.Hash = &bHash
}

func (b *Block) CalcDataHash() {
	tHash := TCollectionHash(b.Data)
	b.DataHash = &tHash
}

func PrintBlock(b *Block) {
	timeFmt := "2006-01-02 15:04:05"

	fmt.Println(fmt.Sprintf(`
Index: %d
Proposer: %s
Timestamp: %s
DataHash: %s
PrevHash: %s
Hash: %s
   `,
		b.Index,
		b.Proposer,
		b.Timestamp.Format(timeFmt),
		PrintHash(b.DataHash),
		PrintHash(b.PrevHash),
		PrintHash(b.Hash),
	))
}

func BlockHash(b *Block) string {
	hash := CalcHash(fmt.Sprintf(
		"%s%s%s%s%s%s",
		b.Index, b.Proposer, b.Timestamp, b.Data, b.DataHash, b.PrevHash,
	))
	return hash
}

func TCollectionHash(tc TCollection) string {
	hash1 := ""
	hash0 := "a"
	for _, t := range tc {
		hash1 = CalcHash(fmt.Sprintf("%s%s", t.Hash(), hash0))
		hash0 = hash1
	} 
	return hash1
}

func NewBlock(prevBlock *Block, proposer string, transactions TCollection) (*Block) {
	var index int
	var prevHash *string
	if prevBlock == nil {
		index = 0
		prevHash = nil
	} else {
		index = prevBlock.Index+1
		prevHash = prevBlock.Hash
	}
	b := Block{
		Index:     index,
		Proposer:  proposer,
		Timestamp: time.Now(),
		Data:      transactions,
		DataHash:  nil,
		PrevHash:  nil,
		Hash:      nil,
	}
	b.CalcDataHash()
	b.CalcHash()
	b.PrevHash = prevHash
	return &b
}

func main() {
	transactions := []Transaction{
		{
			Sender: "user0",
			Msg: &GenericMessage{
				Val: "user0 sent a message",
			},
		},
	}

	block0 := NewBlock(nil, "node0", transactions)
	PrintBlock(block0)

	transactions2 := []Transaction{
		{
			Sender: "user1",
			Msg: &GenericMessage{
				Val: "user1 sent a message",
			},
		},
	}

	block1 := NewBlock(block0, "node0", transactions2)
	PrintBlock(block1)
}
