package btcutil_test

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
)

func ExampleAmount() {

	a := btcutil.Amount(0)
	fmt.Println("Zero Satoshi:", a)

	a = btcutil.Amount(1e8)
	fmt.Println("100,000,000 Satoshis:", a)

	a = btcutil.Amount(1e5)
	fmt.Println("100,000 Satoshis:", a)
	// Output:
	// Zero Satoshi: 0 PPC
	// 100,000,000 Satoshis: 100 PPC
	// 100,000 Satoshis: 0.1 PPC
}

func ExampleNewAmount() {
	amountOne, err := btcutil.NewAmount(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountOne) //Output 1

	amountFraction, err := btcutil.NewAmount(0.012345)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountFraction) //Output 2

	amountZero, err := btcutil.NewAmount(0)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountZero) //Output 3

	amountNaN, err := btcutil.NewAmount(math.NaN())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountNaN) //Output 4

	// Output: 1 PPC
	// 0.012345 PPC
	// 0 PPC
	// invalid peercoin amount
}

func ExampleAmount_unitConversions() {
	amount := btcutil.Amount(44433322211100)

	fmt.Println("Satoshi to kBTC:", amount.Format(btcutil.AmountKiloBTC))
	fmt.Println("Satoshi to BTC:", amount)
	fmt.Println("Satoshi to MilliBTC:", amount.Format(btcutil.AmountMilliBTC))
	fmt.Println("Satoshi to MicroBTC:", amount.Format(btcutil.AmountMicroBTC))
	fmt.Println("Satoshi to Satoshi:", amount.Format(btcutil.AmountSatoshi))

	// Output:
	// Satoshi to kBTC: 44433.3222111 kPPC
	// Satoshi to BTC: 44433322.2111 PPC
	// Satoshi to MilliBTC: 44433322211.1 mPPC
	// Satoshi to MicroBTC: 44433322211100 μPPC
	// Satoshi to Satoshi: 44433322211100 μPPC
}
