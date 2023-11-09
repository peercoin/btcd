package btcutil_test

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
)

func ExampleAmount() {

	a := btcutil.Amount(0)
	fmt.Println("Zero Satoshi:", a)

	a = btcutil.Amount(1e6)
	fmt.Println("1,000,000 Satoshis:", a)

	a = btcutil.Amount(1e3)
	fmt.Println("1,000 Satoshis:", a)
	// Output:
	// Zero Satoshi: 0 PPC
	// 1,000,000 Satoshis: 1 PPC
	// 1,000 Satoshis: 0.001000 PPC
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
	// todo ppc
	amount := btcutil.Amount(44433322211100)

	fmt.Println("Satoshi to kPPC:", amount.Format(btcutil.AmountKiloBTC))
	fmt.Println("Satoshi to PPC:", amount)
	fmt.Println("Satoshi to MilliPPC:", amount.Format(btcutil.AmountMilliBTC))
	fmt.Println("Satoshi to MicroPPC:", amount.Format(btcutil.AmountMicroBTC))
	fmt.Println("Satoshi to Satoshi:", amount.Format(btcutil.AmountSatoshi))

	// Output:
	// Satoshi to kPPC: 44433.3222111 kPPC
	// Satoshi to PPC: 44433322.211100 PPC
	// Satoshi to MilliPPC: 44433322211.1 mPPC
	// Satoshi to MicroPPC: 44433322211100.00 μPPC
	// Satoshi to Satoshi: 4443332221110000.0000 Satoshi
}
