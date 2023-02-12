// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
)

const (
	// Protocol switch time of v0.3 kernel protocol
	nProtocolV03SwitchTime     int64 = 1363800000
	nProtocolV03TestSwitchTime int64 = 1359781000
	// Protocol switch time of v0.4 kernel protocol
	nProtocolV04SwitchTime     int64 = 1399300000
	nProtocolV04TestSwitchTime int64 = 1395700000
	// TxDB upgrade time for v0.4 protocol
	// Note: v0.4 upgrade does not require block chain re-download. However,
	//       user must upgrade before the protocol switch deadline, otherwise
	//       re-download of blockchain is required. The timestamp of upgrade
	//       is recorded in transaction database to alert user of the requirement.
	nProtocolV04UpgradeTime int64 = 0

	// Protocol switch time of v0.5 kernel protocol
	nProtocolV05SwitchTime     int64 = 1461700000
	nProtocolV05TestSwitchTime int64 = 1447700000
	// Protocol switch time of v0.6 kernel protocol
	// supermajority hardfork: actual fork will happen later than switch time
	nProtocolV06SwitchTime     int64 = 1513050000 // Tue 12 Dec 03:40:00 UTC 2017
	nProtocolV06TestSwitchTime int64 = 1508198400 // Tue 17 Oct 00:00:00 UTC 2017
	// Protocol switch time for 0.7 kernel protocol
	nProtocolV07SwitchTime     int64 = 1552392000 // Tue 12 Mar 12:00:00 UTC 2019
	nProtocolV07TestSwitchTime int64 = 1541505600 // Tue 06 Nov 12:00:00 UTC 2018
	// Switch time for new BIPs from bitcoin 0.16.x
	// todo ppc uint32?
	nBTC16BIPsSwitchTime     int64 = 1569931200 // Tue 01 Oct 12:00:00 UTC 2019
	nBTC16BIPsTestSwitchTime int64 = 1554811200 // Tue 09 Apr 12:00:00 UTC 2019
	// Protocol switch time for v0.9 kernel protocol
	nProtocolV09SwitchTime     int64 = 1591617600 // Mon  8 Jun 12:00:00 UTC 2020
	nProtocolV09TestSwitchTime int64 = 1581940800 // Mon 17 Feb 12:00:00 UTC 2020
	// Protocol switch time for v10 kernel protocol
	nProtocolV10SwitchTime     int64 = 1635768000 // Mon  1 Nov 12:00:00 UTC 2021
	nProtocolV10TestSwitchTime int64 = 1625140800 // Thu  1 Jul 12:00:00 UTC 2021
	// Protocol switch time for v12 kernel protocol
	nProtocolV12SwitchTime     int64 = 1681732800 // Mon 17 Apr 12:00:00 UTC 2023
	nProtocolV12TestSwitchTime int64 = 1669636800 // Mon 28 Nov 12:00:00 UTC 2022
)

/*
func getBlockTrust(block *btcutil.Block) *big.Int {
	return calcTrust(block.MsgBlock().Header.Bits, block.MsgBlock().IsProofOfStake())
}
*/

// ppcoin: entropy bit for stake modifier if chosen by modifier
func getStakeEntropyBit(b *BlockChain, block *btcutil.Block) (uint32, error) {

	nEntropyBit := uint32(0)
	hash := block.Hash()

	if IsProtocolV04(b.chainParams, block.MsgBlock().Header.Timestamp.Unix()) {

		nEntropyBit = uint32((HashToBig(hash).Int64()) & 1) // last bit of block hash

		//if (fDebug && GetBoolArg("-printstakemodifier"))
		//    printf("GetStakeEntropyBit(v0.4+): nTime=%d hashBlock=%s entropybit=%d\n", nTime, GetHash().ToString().c_str(), nEntropyBit);

	} else {

		// old protocol for entropy bit pre v0.4
		hashSigBytes := btcutil.Hash160(block.MsgBlock().Signature)
		// to big-endian
		blen := len(hashSigBytes)
		for i := 0; i < blen/2; i++ {
			hashSigBytes[i], hashSigBytes[blen-1-i] = hashSigBytes[blen-1-i], hashSigBytes[i]
		}
		//if (fDebug && GetBoolArg("-printstakemodifier"))
		//    printf("GetStakeEntropyBit(v0.3): nTime=%d hashSig=%s", nTime, hashSig.ToString().c_str());
		hashSig := new(big.Int).SetBytes(hashSigBytes)
		hashSig.Rsh(hashSig, 159) // take the first bit of the hash
		nEntropyBit = uint32(hashSig.Int64())

		//if (fDebug && GetBoolArg("-printstakemodifier"))
		//    printf(" entropybit=%d\n", nEntropyBit)
	}

	log.Tracef("Entropy bit = %d for block %v", nEntropyBit, hash)

	return nEntropyBit, nil
}

func getStakeModifierHexString(stakeModifier uint64) string {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, stakeModifier)
	return hex.EncodeToString(bytes)
}

func getStakeModifierCSHexString(stakeModifierCS uint32) string {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, stakeModifierCS)
	return hex.EncodeToString(bytes)
}

// IsProtocolV03
func IsProtocolV03(chainParams *chaincfg.Params, nTime int64) bool {
	var v03switchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v03switchTime = nProtocolV03TestSwitchTime
	} else {
		v03switchTime = nProtocolV03SwitchTime
	}
	return nTime >= v03switchTime
}

// IsProtocolV04
func IsProtocolV04(chainParams *chaincfg.Params, nTime int64) bool {
	var v04SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v04SwitchTime = nProtocolV04TestSwitchTime
	} else {
		v04SwitchTime = nProtocolV04SwitchTime
	}
	return nTime >= v04SwitchTime
}

func IsProtocolV05(chainParams *chaincfg.Params, nTime int64) bool {
	var v05SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v05SwitchTime = nProtocolV05TestSwitchTime
	} else {
		v05SwitchTime = nProtocolV05SwitchTime
	}
	return nTime >= v05SwitchTime
}

func IsProtocolV06(chainParams *chaincfg.Params, pindexPrev *blockNode) bool {
	var v06SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v06SwitchTime = nProtocolV06TestSwitchTime
	} else {
		v06SwitchTime = nProtocolV06SwitchTime
	}
	if pindexPrev.timestamp < v06SwitchTime {
		return false
	}

	// if 900 of the last 1,000 blocks are version 2 or greater (90/100 if testnet):
	// Soft-forking PoS can be dangerous if the super majority is too low
	// The stake majority will decrease after the fork
	// since only coindays of updated nodes will get destroyed.
	if (chainParams == &chaincfg.MainNetParams && IsSuperMajority(2, pindexPrev, 900, 1000)) ||
		(chainParams != &chaincfg.MainNetParams && IsSuperMajority(2, pindexPrev, 90, 100)) {
		return true
	}

	return false
}

// Whether a given transaction is subject to new v0.7 protocol
func IsProtocolV07(chainParams *chaincfg.Params, nTime int64) bool {
	var v07SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v07SwitchTime = nProtocolV07TestSwitchTime
	} else {
		v07SwitchTime = nProtocolV07SwitchTime
	}
	return nTime >= v07SwitchTime
}

func IsBTC16BIPsEnabled(chainParams *chaincfg.Params, nTime int64) bool {
	var nBTC16SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		nBTC16SwitchTime = nBTC16BIPsTestSwitchTime
	} else {
		nBTC16SwitchTime = nBTC16BIPsSwitchTime
	}
	return nTime >= nBTC16SwitchTime
}

// Whether a given transaction is subject to new v0.9 protocol
func IsProtocolV09(chainParams *chaincfg.Params, nTime int64) bool {
	var v09SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v09SwitchTime = nProtocolV09TestSwitchTime
	} else {
		v09SwitchTime = nProtocolV09SwitchTime
	}
	return nTime >= v09SwitchTime
}

// Whether a given timestamp is subject to new v10 protocol
func IsProtocolV10(chainParams *chaincfg.Params, nTime int64) bool {
	var v10SwitchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		v10SwitchTime = nProtocolV10TestSwitchTime
	} else {
		v10SwitchTime = nProtocolV10SwitchTime
	}
	return nTime >= v10SwitchTime
}

func IsProtocolV12(chainParams *chaincfg.Params, pindexPrev *blockNode) bool {
	// todo ppc couple of spots missing this check
	var switchTime int64
	if chainParams == &chaincfg.TestNet3Params {
		switchTime = nProtocolV12TestSwitchTime
	} else {
		switchTime = nProtocolV12SwitchTime
	}
	if pindexPrev.timestamp < switchTime {
		return false
	}

	// if 900 of the last 1,000 blocks are version 2 or greater (90/100 if testnet):
	// Soft-forking PoS can be dangerous if the super majority is too low
	// The stake majority will decrease after the fork
	// since only coindays of updated nodes will get destroyed.
	if (chainParams == &chaincfg.MainNetParams && IsSuperMajority(4, pindexPrev, 900, 1000)) ||
		(chainParams != &chaincfg.MainNetParams && IsSuperMajority(4, pindexPrev, 90, 100)) {
		return true
	}

	return false
}

// dateTimeStrFormat displays time in RFC3339 format
func dateTimeStrFormat(t int64) string {
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}