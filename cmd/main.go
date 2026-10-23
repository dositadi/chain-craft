package main

import (
	"fmt"

	"github.com/dositadi/chain-craft/internal/chain/account"
)

func main() {
	ciph, _ := account.EncryptWithPassword([]byte("Hello"), []byte("12345"))

	fmt.Println(string(ciph))
}
