// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/txscript"
	// "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	// "github.com/btcsuite/btcd/txscript"
	"math/big"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// Peercoin
const (
	// InitialHashTargetBits TODO(?) golint
	InitialHashTargetBits uint32 = 0x1c00ffff
	// TargetSpacingWorkMax TODO(?) golint
	TargetSpacingWorkMax int64 = StakeTargetSpacing * 12
	// TargetTimespan TODO(?) golint
	TargetTimespan int64 = 7 * 24 * 60 * 60

	// Cent is the number of sunnys in one cent of peercoin
	Cent int64 = 10000
	// Coin is the number of sunnys in one peercoin
	Coin int64 = 100 * Cent
	// MinTxFee is the minimum transaction fee

	PerKbTxFee    int64 = Cent
	MinTxFeePrev7 int64 = Cent
	MinTxFee      int64 = Cent / 10 // todo ppc format
	// MinRelayTxFee is the minimum relayed transaction fee
	MinRelayTxFee int64 = Cent
	// MaxMoney is the max number of sunnys that can be generated
	MaxMoney int64 = 2000000000 * Coin
	// MaxMintProofOfWork is the max number of sunnys that can be POW minted
	MaxMintProofOfWork    int64 = 9999 * Coin
	MaxMintProofOfWorkV10       = 50 * Coin
	// MinTxOutAmount is the minimum output amount required for a transaction
	MinTxOutAmount int64 = MinTxFee

	// FBlockProofOfStake proof of stake blockNode flag (ppc)
	FBlockProofOfStake = uint32(1 << 0)
	// FBlockStakeEntropy entropy bit for stake modifier blockNode flag (ppc)
	FBlockStakeEntropy = uint32(1 << 1)
	// FBlockStakeModifier regenerated stake modifier blockNode flag (ppc)
	FBlockStakeModifier = uint32(1 << 2)
	// ASERT half life
	nDAAHalfLife int64 = 24 * 60 * 60
)

// Stake TODO(?) golint
type Stake struct {
	outPoint wire.OutPoint
	time     int64
}

type processPhase int

const (
	phasePreSanity processPhase = iota
)

func getProofOfStakeFromBlock(block *btcutil.Block) Stake {
	if block.IsProofOfStake() {
		tx := block.Transactions()[1].MsgTx()
		return Stake{tx.TxIn[0].PreviousOutPoint, tx.Timestamp.Unix()}
	}
	return Stake{}
}

var stakeSeen, stakeSeenOrphan = make(map[Stake]bool), make(map[Stake]bool)

// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L894
// peercoin: find last block index up to pindex
func getLastBlockIndex(pindex HeaderCtx, fProofOfStake bool) HeaderCtx {

	for pindex != nil && pindex.Parent() != nil && pindex.IsProofOfStake() != fProofOfStake {
		pindex = pindex.Parent()
	}
	return pindex
}

func (b *BlockChain) GetLastBlockIndex(hash *chainhash.Hash, fProofOfStake bool) *chainhash.Hash {
	return getLastBlockIndex(b.index.LookupNode(hash), fProofOfStake).Hash()
}

var (
	cachedAnchor atomic.Value // *blockNode
)

// ResetASERTAnchorBlockCache resets the cached anchor block
func ResetASERTAnchorBlockCache() {
	cachedAnchor.Store((*blockNode)(nil))
}

// CalculateASERT calculates the next target using ASERT
func CalculateASERT(refTarget, powLimit *big.Int, nPowTargetSpacing, nTimeDiff, nHeightDiff, nHalfLife int64) *big.Int {
	// Input target must never be zero nor exceed powLimit.
	if refTarget.Sign() <= 0 || refTarget.Cmp(powLimit) > 0 {
		panic("Invalid refTarget")
	}

	// We need some leading zero bits in powLimit to handle overflows easily.
	// 28 leading zero bits should be enough.
	if new(big.Int).Rsh(powLimit, 228).Sign() != 0 {
		panic("powLimit doesn't have enough leading zero bits")
	}

	// Height diff should NOT be negative.
	if nHeightDiff < 0 {
		panic("Negative nHeightDiff")
	}

	// Calculate the exponent
	exponent := nTimeDiff - nPowTargetSpacing*(nHeightDiff+1)
	exponent = (exponent * 65536) / nHalfLife

	// Calculate shifts and fractional part
	shifts := exponent >> 16
	frac := uint64(uint16(exponent))

	// Calculate the factor
	factor := uint64(65536)
	factor += (195766423245049*frac + 971821376*(frac*frac) + 5127*(frac*frac*frac) + (1 << 47)) >> 48

	// Calculate nextTarget
	nextTarget := new(big.Int).Mul(refTarget, big.NewInt(int64(factor)))

	// Adjust shifts
	shifts -= 16
	if shifts <= 0 {
		nextTarget.Rsh(nextTarget, uint(-shifts))
	} else {
		// Check for overflow
		nextTargetShifted := new(big.Int).Lsh(nextTarget, uint(shifts))
		if nextTargetShifted.Rsh(nextTargetShifted, uint(shifts)).Cmp(nextTarget) != 0 {
			// Overflow occurred, set to powLimit
			nextTarget.Set(powLimit)
		} else {
			nextTarget.Set(nextTargetShifted)
		}
	}

	// Ensure nextTarget is at least 1 and at most powLimit
	if nextTarget.Sign() == 0 {
		nextTarget.SetInt64(1)
	} else if nextTarget.Cmp(powLimit) > 0 {
		nextTarget.Set(powLimit)
	}

	return nextTarget
}

// GetNextASERTWorkRequired calculates the next required work
func GetNextASERTWorkRequired(pindexPrev *blockNode, pindex *blockNode, chainParams *chaincfg.Params) uint32 {
	return GetNextASERTWorkRequiredWithAnchor(pindexPrev, pindex, chainParams, GetASERTAnchorBlock(pindexPrev, chainParams))
}

// GetNextASERTWorkRequiredWithAnchor calculates the next required work with a given anchor block
func GetNextASERTWorkRequiredWithAnchor(pindexPrev *blockNode, pindex *blockNode, chainParams *chaincfg.Params, pindexAnchorBlock *blockNode) uint32 {
	// This cannot handle the genesis block and early blocks in general.
	if pindexPrev == nil {
		panic("pindexPrev is nil")
	}

	// Anchor block is the block on which all ASERT scheduling calculations are based.
	// It too must exist, and it must have a valid parent.
	if pindexAnchorBlock == nil {
		panic("pindexAnchorBlock is nil")
	}

	// We make no further assumptions other than the height of the prev block
	// must be >= that of the anchor block.
	if int32(pindexPrev.Height()) < int32(pindexAnchorBlock.Height()) {
		panic("pindexPrev.Height < pindexAnchorBlock.Height")
	}

	powLimit := chainParams.PowLimit

	// For nTimeDiff calculation, use the parent of the anchor block timestamp.
	var anchorTime int64
	if pindexAnchorBlock.parent != nil {
		anchorTime = pindexAnchorBlock.parent.timestamp
	} else {
		anchorTime = pindexAnchorBlock.timestamp
	}

	nTimeDiff := pindex.timestamp - anchorTime

	// Height difference is from current block to anchor block
	nHeightDiff := pindexPrev.height - pindexAnchorBlock.height -
		(pindexPrev.heightStake - pindexAnchorBlock.heightStake)

	// Convert nBits to big.Int
	refBlockTarget := CompactToBig(pindexAnchorBlock.bits)

	// Do the actual target adaptation calculation in CalculateASERT function
	nextTarget := CalculateASERT(
		refBlockTarget,
		powLimit,
		StakeTargetSpacing*6,
		nTimeDiff,
		int64(nHeightDiff),
		nDAAHalfLife,
	)

	// Convert back to compact representation
	return BigToCompact(nextTarget)
}

// GetASERTAnchorBlock finds the appropriate anchor block for ASERT calculations
func GetASERTAnchorBlock(pindex *blockNode, chainParams *chaincfg.Params) *blockNode {
	cachedValue := cachedAnchor.Load()
	if cachedValue != nil {
		if lastCached, ok := cachedValue.(*blockNode); ok {
			if pindex.Ancestor(lastCached.height) == lastCached {
				return lastCached
			}
		}
	}

	anchor := pindex
	for anchor.parent != nil {
		if !IsProtocolV14(chainParams, anchor.parent) && !anchor.IsProofOfStake() {
			break
		}
		anchor = anchor.parent
	}

	cachedAnchor.Store(anchor)
	return anchor
}

// calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous block node based on the difficulty retarget rules.
// This function differs from the exported CalcNextRequiredDifficulty in that
// the exported version uses the current best chain as the previous block node
// while this function accepts any block node.
// Peercoin https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L902
func calcNextRequiredDifficultyPPC(lastNode HeaderCtx, proofOfStake bool, c ChainCtx) (uint32, error) {

	if lastNode == nil {
		return c.ChainParams().PowLimitBits, nil // genesis block
	}

	prev := getLastBlockIndex(lastNode, proofOfStake)
	if prev.Hash().IsEqual(c.ChainParams().GenesisHash) {
		return c.ChainParams().InitialHashTargetBits, nil // first block
	}
	prevParent := prev.Parent()
	prevPrev := getLastBlockIndex(prevParent, proofOfStake)
	if prevPrev.Hash().IsEqual(c.ChainParams().GenesisHash) {
		return c.ChainParams().InitialHashTargetBits, nil // second block
	}

	if !proofOfStake && IsProtocolV14(c.ChainParams(), prev) {
		prevNodeTmp := c.index.LookupNode(prev.Hash())
		lastNodeTmp := c.index.LookupNode(lastNode.Hash())

		return GetNextASERTWorkRequired(prevNodeTmp, lastNodeTmp, c.ChainParams()), nil
	}

	actualSpacing := prev.Timestamp() - prevPrev.Timestamp()

	nHypotheticalSpacing := lastNode.Timestamp() - prev.Timestamp()
	if !proofOfStake && IsProtocolV12(c.ChainParams(), prev) && (nHypotheticalSpacing > actualSpacing) {
		actualSpacing = nHypotheticalSpacing
	}

	newTarget := CompactToBig(prev.Bits())
	var targetSpacing int64
	if proofOfStake {
		targetSpacing = StakeTargetSpacing
	} else {
		if IsProtocolV09(c.ChainParams(), lastNode.Timestamp()) {
			targetSpacing = StakeTargetSpacing * 6
		} else {
			targetSpacing = minInt64(TargetSpacingWorkMax, StakeTargetSpacing*(int64(1+lastNode.Height()-prev.Height())))
		}
	}
	interval := TargetTimespan / targetSpacing
	targetSpacingBig := big.NewInt(targetSpacing)
	intervalMinusOne := big.NewInt(interval - 1)
	intervalPlusOne := big.NewInt(interval + 1)
	tmp := new(big.Int).Mul(intervalMinusOne, targetSpacingBig)
	tmp.Add(tmp, big.NewInt(actualSpacing+actualSpacing))
	newTarget.Mul(newTarget, tmp)
	newTarget.Div(newTarget, new(big.Int).Mul(intervalPlusOne, targetSpacingBig))

	if newTarget.Cmp(c.ChainParams().PowLimit) > 0 {
		newTarget = c.ChainParams().PowLimit
	}

	return BigToCompact(newTarget), nil
}

/*
// CalcNextRequiredDifficulty calculates the required difficulty for the block
// after the end of the current best chain based on the difficulty retarget
// rules.
//
// This function is NOT safe for concurrent access. Use blockmanager.
func (b *BlockChain) PPCCalcNextRequiredDifficulty(proofOfStake bool) (uint32, error) {
	return b.calcNextRequiredDifficultyPPC(b.bestChain, proofOfStake)
}
*/

/*
// setCoinbaseMaturity sets required coinbase maturity and return old one
// Export required for tests only
func (b *BlockChain) SetCoinbaseMaturity(coinbaseMaturity int64) (old int64) {
	old = b.chainParams.CoinbaseMaturity
	b.chainParams.CoinbaseMaturity = coinbaseMaturity
	return
}
*/

// calcTrust calculates a work value from difficulty bits.  Bitcoin increases
// the difficulty for generating a block by decreasing the value which the
// generated hash must be less than.  This difficulty target is stored in each
// block header using a compact representation as described in the documenation
// for CompactToBig.  The main chain is selected by choosing the chain that has
// the most proof of work (highest difficulty).  Since a lower target difficulty
// value equates to higher actual difficulty, the work value which will be
// accumulated must be the inverse of the difficulty.  Also, in order to avoid
// potential division by zero and really small floating point numbers, the
// result adds 1 to the denominator and multiplies the numerator by 2^256.
func calcTrust(bits uint32, proofOfStake bool) *big.Int {
	// Return a work value of zero if the passed difficulty bits represent
	// a negative number. Note this should not happen in practice with valid
	// blocks, but an invalid block could trigger it.
	difficultyNum := CompactToBig(bits)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}
	if !proofOfStake {
		return new(big.Int).SetInt64(1)
	}
	// (1 << 256) / (difficultyNum + 1)
	denominator := new(big.Int).Add(difficultyNum, bigOne)
	return new(big.Int).Div(oneLsh256, denominator)
}

// calcMintAndMoneySupply TODO(?) golint
func (b *BlockChain) calcMintAndMoneySupply(block *btcutil.Block, prevHash *chainhash.Hash) error {

	nFees := int64(0)
	nValueIn := int64(0)
	nValueOut := int64(0)

	utxoView := NewUtxoViewpoint()
	err := utxoView.fetchInputUtxos(b.db, block)
	if err != nil {
		return err
	}

	transactions := block.Transactions()
	for _, tx := range transactions {

		nTxValueOut := int64(0)
		for _, txOut := range tx.MsgTx().TxOut {
			nTxValueOut += txOut.Value
		}

		if IsCoinBase(tx) {
			nValueOut += nTxValueOut
		} else {
			nTxValueIn := int64(0)
			for _, txIn := range tx.MsgTx().TxIn {
				originTx := utxoView.LookupEntry(txIn.PreviousOutPoint)
				if originTx == nil {
					err = fmt.Errorf("calcMintAndMoneySupply(): failed to find outpoint for %s", txIn.PreviousOutPoint.Hash)
					return err
				}
				nTxValueIn += originTx.Amount()
			}
			nValueIn += nTxValueIn
			nValueOut += nTxValueOut
			if !IsCoinStake(tx) {
				nFees += nTxValueIn - nTxValueOut
			}
		}
	}

	log.Debugf("height = %v, nValueIn = %v, nValueOut = %v, nFees = %v", block.Height(), nValueIn, nValueOut, nFees)

	// peercoin: track money supply and mint amount info
	block.Meta().Mint = nValueOut - nValueIn + nFees
	var prevNode *blockNode
	prevNode = b.index.LookupNode(prevHash)

	if prevNode == nil {
		block.Meta().MoneySupply = nValueOut - nValueIn
	} else {
		if prevNode.meta.MoneySupply == 0 {
			// reorganizing the chain means an unconnected node might not contain meta info yet, so we look up the full block
			var prevBlock *btcutil.Block
			err = b.db.View(func(dbTx database.Tx) error {
				var err error
				prevBlock, err = dbFetchBlockByNode(dbTx, prevNode)
				return err
			})
			if err != nil {
				return err
			}
			block.Meta().MoneySupply = prevBlock.Meta().MoneySupply + nValueOut - nValueIn
		} else {
			block.Meta().MoneySupply = prevNode.meta.MoneySupply + nValueOut - nValueIn
		}
	}

	log.Debugf("height = %v, mint = %v, moneySupply = %v", block.Height(), block.Meta().Mint, block.Meta().MoneySupply)

	return nil
}

// peercoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
func getCoinAgeTx(tx *btcutil.Tx, nTimeTx int64, utxoView *UtxoViewpoint, chainParams *chaincfg.Params, isTrueCoinAge bool) (int64, error) {

	bnCentSecond := big.NewInt(0) // coin age in the unit of cent-seconds

	if IsCoinBase(tx) {
		return 0, nil
	}

	for _, txIn := range tx.MsgTx().TxIn {
		// First try finding the previous transaction in database
		txPrev := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if txPrev == nil {
			continue // previous transaction not in main chain
		}
		txPrevTime := txPrev.Timestamp().Unix()
		if nTimeTx < txPrevTime {
			err := fmt.Errorf("Transaction timestamp violation")
			return 0, err // Transaction timestamp violation
		}
		// todo ppc v3 tx does not carry timestamps, use block instead
		// todo ppc verify Timestamp does what we need it to
		// todo ppc this might be too lax. we either need blocktime in utxoview or another way to fetch the block itself
		if txPrev.Timestamp().Unix()+chainParams.StakeMinAge > nTimeTx {
			continue // only count coins meeting min age requirement
		}

		// todo ppc this is probably wrong
		// txPrevIndex := txIn.PreviousOutPoint.Index
		nValueIn := txPrev.Amount()
		effectiveAge := nTimeTx - txPrevTime
		if !isTrueCoinAge || IsProtocolV09(chainParams, nTimeTx) {
			effectiveAge = minInt64(effectiveAge, 365*24*60*60)
		}
		nValueInBig := big.NewInt(nValueIn)
		nEffectiveAgeBig := big.NewInt(effectiveAge)
		mulResult := new(big.Int).Mul(nValueInBig, nEffectiveAgeBig)
		divResult := new(big.Int).Div(mulResult, big.NewInt(Cent))
		bnCentSecond.Add(bnCentSecond, divResult)

		log.Debugf("coin age nValueIn=%v nTimeDiff=%v bnCentSecond=%v", nValueIn, txPrevTime, bnCentSecond.String()) // todo ppc v3
	}

	bnCoinDay := new(big.Int).Mul(bnCentSecond, big.NewInt(Cent)).Div(new(big.Int).Mul(bnCentSecond, big.NewInt(Cent)),
		big.NewInt(Coin*24*60*60))
	log.Debugf("coin age bnCoinDay=%v", bnCoinDay.String())

	return bnCoinDay.Int64(), nil
}

/*
// peercoin: total coin age spent in block, in the unit of coin-days.
func (b *BlockChain) getCoinAgeBlock(node *blockNode, block *btcutil.Block) (uint64, error) {


	txStore, err := b.fetchInputTransactions(node, block)
	if err != nil {
		return 0, err
	}

	nCoinAge := uint64(0)

	transactions := block.Transactions()
	for _, tx := range transactions {
		nTxCoinAge, err := b.getCoinAgeTx(tx, txStore)
		if err != nil {
			return 0, err
		}
		nCoinAge += nTxCoinAge
	}

	if nCoinAge == 0 { // block coin age minimum 1 coin-day
		nCoinAge = 1
	}

	log.Debugf("block coin age total nCoinDays=%v", nCoinAge)

	return nCoinAge, nil
}
*/

// PPCGetProofOfStakeReward
// Export requited, used my ppcwallet createCoinStake method
func PPCGetProofOfStakeReward(nCoinAge int64) btcutil.Amount {
	nRewardCoinYear := Cent // creation amount per coin-year
	nSubsidy := nCoinAge * 33 / (365*33 + 8) * nRewardCoinYear

	// todo ppc this function isn't used currently. once it is, add IsProtocolV09

	log.Debugf("getProofOfStakeReward(): create=%v nCoinAge=%v", nSubsidy, nCoinAge)
	return btcutil.Amount(nSubsidy)
}

// peercoin: miner's coin stake is rewarded based on coin age spent (coin-days)
func getProofOfStakeReward(chainParams *chaincfg.Params, nTime int64, nCoinAge int64, moneySupply int64) int64 {
	nRewardCoinYear := Cent // creation amount per coin-year
	nSubsidy := nCoinAge * 33 / (365*33 + 8) * nRewardCoinYear

	if IsProtocolV09(chainParams, nTime) {
		// rfc18
		// YearlyBlocks = ((365 * 33 + 8) / 33) * 1440 / 10
		// some efforts not to lose precision
		bnInflationAdjustment := big.NewInt(moneySupply)
		bnInflationAdjustment.Mul(bnInflationAdjustment, big.NewInt(25*33))
		bnInflationAdjustment.Div(bnInflationAdjustment, big.NewInt(10000*144))
		bnDaysPerYear := big.NewInt(365*33 + 8)
		bnInflationAdjustment.Div(bnInflationAdjustment, bnDaysPerYear)

		nInflationAdjustment := bnInflationAdjustment.Int64()
		nSubsidyNew := (nSubsidy * 3) + nInflationAdjustment

		log.Debugf("getProofOfStakeReward(): money supply %v, inflation adjustment %v, old subsidy %v, new subsidy %v\n", moneySupply, nInflationAdjustment/1000000.0, nSubsidy, nSubsidyNew)

		nSubsidy = nSubsidyNew
	}

	log.Debugf("getProofOfStakeReward(): create=%v nCoinAge=%v", nSubsidy, nCoinAge)
	return nSubsidy
}

// IsCoinStake determines whether or not a transaction is a coinstake.  A coinstake
// is a special transaction created by peercoin minters.
// Export required as it is used in ppcwallet
func IsCoinStakeTx(tx *wire.MsgTx) bool {
	return tx.IsCoinStake()
}

// IsCoinStake determines whether or not a transaction is a coinstake.  A coinstake
// is a special transaction created by peercoin minters.
// Export required as it is used in mempool.go
func IsCoinStake(tx *btcutil.Tx) bool {
	return IsCoinStakeTx(tx.MsgTx())
}

// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.h#L962
// peercoin: two types of block: proof-of-work or proof-of-stake
func (block *blockNode) isProofOfStake() bool {
	return isProofOfStake(block.meta)
}

// peercoin: two types of block: proof-of-work or proof-of-stake
func isProofOfStake(meta *wire.Meta) bool {
	return meta.Flags&FBlockProofOfStake != 0
}

// setProofOfStake
func setProofOfStake(meta *wire.Meta, proofOfStake bool) {
	if proofOfStake {
		meta.Flags |= FBlockProofOfStake
	} else {
		meta.Flags &^= FBlockProofOfStake
	}
}

// isGeneratedStakeModifier
func isGeneratedStakeModifier(meta *wire.Meta) bool {
	return meta.Flags&FBlockStakeModifier != 0
}

// setGeneratedStakeModifier
func setGeneratedStakeModifier(meta *wire.Meta, generated bool) {
	if generated {
		meta.Flags |= FBlockStakeModifier
	} else {
		meta.Flags &^= FBlockStakeModifier
	}
}

// getMetaStakeEntropyBit
func getMetaStakeEntropyBit(meta *wire.Meta) uint32 {
	if meta.Flags&FBlockStakeEntropy != 0 {
		return 1
	}
	return 0
}

// setMetaStakeEntropyBit
func setMetaStakeEntropyBit(meta *wire.Meta, entropyBit uint32) {
	if entropyBit == 0 {
		meta.Flags &^= FBlockStakeEntropy
	} else {
		meta.Flags |= FBlockStakeEntropy
	}
}

// bigToShaHash converts a big.Int into a chainhash.Hash.
func bigToShaHash(value *big.Int) (*chainhash.Hash, error) {

	buf := value.Bytes()

	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}

	// Make sure the byte slice is the right length by appending zeros to
	// pad it out.
	pbuf := buf
	if chainhash.HashSize-blen > 0 {
		pbuf = make([]byte, chainhash.HashSize)
		copy(pbuf, buf)
	}

	return chainhash.NewHash(pbuf)
}

// PPCGetLastProofOfWorkReward
// Export required, used in ppcwallet CreateCoinStake method
// todo ppc unused -> ppcGetLastProofOfWorkRewardMsg in netsync
/*
func (b *BlockChain) PPCGetLastProofOfWorkReward() (subsidy int64) {
	lastPOWNode := b.getLastBlockIndex(b.bestChain.Tip(), false)
	return PPCGetProofOfWorkReward(lastPOWNode.bits, lastPOWNode.timestamp, b.chainParams)
}
*/

// ppcGetProofOfWorkReward is Peercoin's validate.go:CalcBlockSubsidy(...)
// counterpart.
// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L829
// Export required, used in NewBlockTemplate method
func PPCGetProofOfWorkReward(nBits uint32, nTime int64, chainParams *chaincfg.Params) (subsidy int64) {
	// todo ppc verify
	bigTwo := new(big.Int).SetInt64(2)
	bnSubsidyLimit := new(big.Int).SetInt64(MaxMintProofOfWork)
	bnTarget := CompactToBig(nBits)
	bnTargetLimit := chainParams.PowLimit
	// TODO(kac-) wat? bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());
	bnTargetLimit = CompactToBig(BigToCompact(bnTargetLimit))
	// peercoin: subsidy is cut in half every 16x multiply of difficulty
	// A reasonably continuous curve is used to avoid shock to market
	// (nSubsidyLimit / nSubsidy) ** 4 == bnProofOfWorkLimit / bnTarget
	bnLowerBound := new(big.Int).SetInt64(Cent)
	bnUpperBound := new(big.Int).Set(bnSubsidyLimit)
	for new(big.Int).Add(bnLowerBound, new(big.Int).SetInt64(Cent)).Cmp(bnUpperBound) <= 0 {
		bnMidValue := new(big.Int).Div(new(big.Int).Add(bnLowerBound, bnUpperBound), bigTwo)
		/*
			if (fDebug && GetBoolArg("-printcreation"))
			printf("GetProofOfWorkReward() : lower=%"PRI64d" upper=%"PRI64d" mid=%"PRI64d"\n", bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());
		*/
		mid := new(big.Int).Set(bnMidValue)
		sub := new(big.Int).Set(bnSubsidyLimit)
		//if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnTargetLimit > bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnTarget)
		if mid.Mul(mid, mid).Mul(mid, mid).Mul(mid, bnTargetLimit).Cmp(sub.Mul(sub, sub).Mul(sub, sub).Mul(sub, bnTarget)) > 0 {
			bnUpperBound = bnMidValue
		} else {
			bnLowerBound = bnMidValue
		}
	}
	subsidy = bnUpperBound.Int64()
	subsidy = (subsidy / Cent) * Cent

	// nSubsidy = std::min(nSubsidy, IsProtocolV10(nTime) ? MAX_MINT_PROOF_OF_WORK_V10 : MAX_MINT_PROOF_OF_WORK);
	var maxMint int64 // todo ppc verified,
	if IsProtocolV10(chainParams, nTime) {
		maxMint = MaxMintProofOfWorkV10
	} else {
		maxMint = MaxMintProofOfWork
	}
	subsidy = minInt64(subsidy, maxMint)

	if subsidy > MaxMintProofOfWork {
		subsidy = MaxMintProofOfWork
	}
	return
}

// GetMinFee calculates minimum required required for transaction.
// Export required, used in ppcwallet createCoinStake method
func GetMinFee(tx *wire.MsgTx) int64 {
	// todo ppc protov07
	baseFee := MinTxFee
	bytes := tx.SerializeSize()
	minFee := (1 + int64(bytes)/1000) * baseFee
	return minFee
}

// getMinFee calculates minimum required required for transaction.
// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.h#L592
// Export required, used in ppcwallet createCoinStake method
func getMinFee(tx *btcutil.Tx, chainParams *chaincfg.Params) int64 {
	baseFee := MinTxFee
	bytes := tx.MsgTx().SerializeSize()
	var minFee int64
	if IsProtocolV07(chainParams, tx.MsgTx().Timestamp.Unix()) || tx.MsgTx().Timestamp.Unix() == 0 {
		if bytes < 100 {
			minFee = MinTxFee
		} else {
			minFee = int64(bytes) * (MinTxFee / 1000)
		}
	} else {
		minFee = (1 + int64(bytes)/1000) * baseFee
	}
	if minFee > MaxMoney {
		minFee = MaxMoney
	}
	return minFee
}

// checkBlockSignature ppc: check block signature
// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L2116
// Export required for tests only
func CheckBlockSignature(msgBlock *wire.MsgBlock,
	params *chaincfg.Params) bool {
	hash := msgBlock.BlockHash()
	if hash.IsEqual(params.GenesisHash) {
		return len(msgBlock.Signature) == 0
	}
	var txOut *wire.TxOut
	if msgBlock.IsProofOfStake() {
		txOut = msgBlock.Transactions[1].TxOut[1]
	} else {
		txOut = msgBlock.Transactions[0].TxOut[0]
	}
	scriptClass, addresses, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, params)
	if err != nil {
		return false
	}
	if scriptClass != txscript.PubKeyTy {
		return false
	}
	a, ok := addresses[0].(*btcutil.AddressPubKey)
	if !ok {
		return false
	}
	// todo ppc btcec.ParseSignature(msgBlock.Signature, btcec.S256()) -> ecdsa.ParseSignature(msgBlock.Signature)
	sig, err := ecdsa.ParseSignature(msgBlock.Signature)
	if err != nil {
		return false
	}
	return sig.Verify(hash[:], a.PubKey())
}

/* todo ppc this is used upstream
     we don't really need it
func IsZeroAllowed(nTimeTx int64) bool {
	return nTimeTx >= 1447700000 // very crude approximation to prevent linking with kernel.cpp
}
*/

// Peercoin additional context free transaction checks.
// Basing on CTransaction::CheckTransaction().
// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L445
func ppcCheckTransactionSanity(chainParams *chaincfg.Params, tx *btcutil.Tx) error { // todo ppc add more rules where needed
	msgTx := tx.MsgTx()
	for _, txOut := range msgTx.TxOut {
		// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L461
		// if (txout.IsEmpty() && (!IsCoinBase()) && (!IsCoinStake()))
		// 	return DoS(100, error("CTransaction::CheckTransaction() : txout empty for user transaction"));
		if txOut.IsEmpty() && !IsCoinBase(tx) && !IsCoinStake(tx) {
			str := "transaction output empty for user transaction"
			return ruleError(ErrEmptyTxOut, str)
		}

		// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L463
		// peercoin: enforce minimum output amount
		// if ((!txout.IsEmpty()) && txout.nValue < MIN_TXOUT_AMOUNT)
		// 	return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue below minimum"));
		if (!txOut.IsEmpty()) && txOut.Value < MinTxOutAmount &&
			(msgTx.Version < 3 && !(IsProtocolV05(chainParams, msgTx.Timestamp.Unix()) && txOut.Value == 0)) {
			str := fmt.Sprintf("transaction output value of %v is below minimum %v",
				txOut.Value, MinTxOutAmount)
			return ruleError(ErrBadTxOutValue, str)
		}
	}
	return nil
}

// Peercoin additional transaction checks.
// Basing on CTransaction::ConnectInputs().
// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1149
func ppcCheckTransactionInputs(tx *btcutil.Tx, nTimeTx int64, utxoView *UtxoViewpoint, moneySupply int64,
	satoshiIn int64, satoshiOut int64, chainParams *chaincfg.Params) error {
	// todo ppc missing a bunch of rules -> bool Consensus::CheckTxInputs()
	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1230
	// peercoin: coin stake tx earns reward instead of paying fee
	// if (IsCoinStake())
	// {
	// uint64 nCoinAge;
	// if (!GetCoinAge(txdb, nCoinAge))
	// 	return error("ConnectInputs() : %s unable to get coin age for coinstake", GetHash().ToString().substr(0,10).c_str());
	// int64 nStakeReward = GetValueOut() - nValueIn;
	// if (nStakeReward > getProofOfStakeReward(nCoinAge) - GetMinFee() + MIN_TX_FEE)
	// 	return DoS(100, error("ConnectInputs() : %s stake reward exceeded", GetHash().ToString().substr(0,10).c_str()));
	// }
	if IsCoinStake(tx) {
		coinAge, err := getCoinAgeTx(tx, nTimeTx, utxoView, chainParams, true)
		if err != nil {
			return fmt.Errorf("unable to get coin age for coinstake: %w", err)
		}
		stakeReward := satoshiOut - satoshiIn

		coinstakeCost := getMinFee(tx, chainParams)
		if coinstakeCost < PerKbTxFee {
			coinstakeCost = 0
		} else {
			coinstakeCost -= PerKbTxFee
		}

		maxReward := getProofOfStakeReward(chainParams, nTimeTx, coinAge, moneySupply) - coinstakeCost
		if moneySupply != 0 && stakeReward > maxReward { // todo ppc: moneySupply of 0 can also indicate that our input is garbage, and that it should be double checked beforehand. should be removed if not needed.
			str := fmt.Sprintf("%v stake reward value %v exceeded %v", tx.Hash(), stakeReward, maxReward)
			return ruleError(ErrBadCoinstakeValue, str)
		}
	} else {
		// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1249
		// peercoin: enforce transaction fees for every block
		// if (nTxFee < GetMinFee())
		// 	return fBlock? DoS(100, error("ConnectInputs() : %s not paying required fee=%s, paid=%s", GetHash().ToString().substr(0,10).c_str(), FormatMoney(GetMinFee()).c_str(), FormatMoney(nTxFee).c_str())) : false;
		txFee := satoshiIn - satoshiOut
		if txFee < getMinFee(tx, chainParams) { // todo ppc
			str := fmt.Sprintf("%v not paying required fee=%v, paid=%v", tx.Hash(), getMinFee(tx, chainParams), txFee)
			return ruleError(ErrInsufficientFee, str)
		}
	}
	return nil
}

func ppcCheckTransactionInput(nTimeTx int64, originUtxo *UtxoEntry) error {
	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1177
	// peercoin: check transaction timestamp
	// if (txPrev.nTime > nTime)
	// 	return DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));
	// todo ppc I added timestamp to utxoview, and it might not be accurate.
	// todo ppc verify there's no checks missing
	if originUtxo.Timestamp().Unix() > nTimeTx {
		str := "transaction timestamp earlier than input transaction"
		return ruleError(ErrEarlierTimestamp, str)
	}
	return nil
}

// Peercoin additional context free block checks.
// Basing on CBlock::CheckBlock().
// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1829
func ppcCheckBlockSanity(chainParams *chaincfg.Params, block *btcutil.Block) error {
	msgBlock := block.MsgBlock()
	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1853
	// peercoin: only the second transaction can be the optional coinstake
	// for (int i = 2; i < vtx.size(); i++)
	// 	if (vtx[i].IsCoinStake())
	// 		return DoS(100, error("CheckBlock() : coinstake in wrong position"));
	for i := 2; i < len(msgBlock.Transactions); i++ {
		if msgBlock.Transactions[i].IsCoinStake() {
			str := "coinstake in wrong position"
			return ruleError(ErrWrongCoinstakePosition, str)
		}
	}

	var nTimeTxZero int64 // todo ppc verify
	if msgBlock.Transactions[0].Timestamp.Unix() != 0 {
		nTimeTxZero = msgBlock.Transactions[0].Timestamp.Unix()
	} else {
		nTimeTxZero = msgBlock.Header.Timestamp.Unix()
	}

	var nTimeTxOne int64 // todo ppc verify
	if len(msgBlock.Transactions) > 1 && msgBlock.Transactions[1].Timestamp.Unix() != 0 {
		nTimeTxOne = msgBlock.Transactions[1].Timestamp.Unix()
	} else {
		nTimeTxOne = msgBlock.Header.Timestamp.Unix()
	}

	var maxFutureBlockTime int64 // todo ppc verify
	if IsProtocolV09(chainParams, msgBlock.Header.Timestamp.Unix()) {
		maxFutureBlockTime = MaxFutureBlockTime
	} else {
		maxFutureBlockTime = MaxFutureBlockTimePrev09
	}

	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1858
	// peercoin: first coinbase output should be empty if proof-of-stake block
	// if (block.IsProofOfStake() && !block.vtx[0]->vout[0].IsEmpty())
	//    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-notempty", "coinbase output not empty in PoS block");
	if block.IsProofOfStake() && !msgBlock.Transactions[0].TxOut[0].IsEmpty() {
		str := "coinbase output not empty for proof-of-stake block"
		return ruleError(ErrCoinbaseNotEmpty, str)
	}

	/*
	   // Check coinbase timestamp
	   if (block.GetBlockTime() > (block.vtx[0]->nTime ? (int64_t)block.vtx[0]->nTime : block.GetBlockTime()) + (IsProtocolV09(block.GetBlockTime()) ? MAX_FUTURE_BLOCK_TIME : MAX_FUTURE_BLOCK_TIME_PREV9))
	       return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-time", "coinbase timestamp is too early");
	*/
	// todo ppc verify
	if msgBlock.Header.Timestamp.Unix() > (nTimeTxZero + maxFutureBlockTime) {
		str := "coinbase timestamp is too early"
		return ruleError(ErrCoinbaseTimeViolation, str)
	}

	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1866
	// Check coinstake timestamp
	// if (IsProofOfStake() && !CheckCoinStakeTimestamp(GetBlockTime(), (int64)vtx[1].nTime))
	// 	return DoS(50, error("CheckBlock() : coinstake timestamp violation nTimeBlock=%u nTimeTx=%u", GetBlockTime(), vtx[1].nTime));
	if block.IsProofOfStake() && !checkCoinStakeTimestamp(chainParams, msgBlock.Header.Timestamp.Unix(), nTimeTxOne) {
		str := fmt.Sprintf("coinstake timestamp violation TimeBlock=%v TimeTx=%v",
			msgBlock.Header.Timestamp, nTimeTxOne)
		return ruleError(ErrCoinstakeTimeViolation, str)
	}

	for _, tx := range msgBlock.Transactions {
		// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1881
		// peercoin: check transaction timestamp
		// if (GetBlockTime() < (int64)tx.nTime)
		//  return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
		if msgBlock.Header.Timestamp.Before(tx.Timestamp) {
			str := "block timestamp earlier than transaction timestamp"
			return ruleError(ErrBlockBeforeTx, str)
		}
	}
	// peercoin: check block signature
	// if (fCheckMerkleRoot && fCheckSignature && (block.IsProofOfStake() || !IsBTC16BIPsEnabled(block.GetBlockTime())) && !CheckBlockSignature(block))
	//     return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sign", strprintf("%s : bad block signature", __func__));
	// todo ppc enable for PoW blocks?
	if (block.IsProofOfStake() || !IsBTC16BIPsEnabled(chainParams, msgBlock.Header.Timestamp.Unix())) && !CheckBlockSignature(msgBlock, chainParams) {
		str := "bad block signature"
		return ruleError(ErrBadBlockSignature, str)
	}
	return nil
}

func (b *BlockChain) ppcProcessOrphan(block *btcutil.Block) error {
	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L2036
	// peercoin: check proof-of-stake
	if block.IsProofOfStake() {
		// Limited duplicity on stake: prevents block flood attack
		// Duplicate stake allowed only when there is orphan child block
		sha := block.Hash()
		stake := getProofOfStakeFromBlock(block)
		_, seen := stakeSeen[stake]
		children, hasChild := b.prevOrphans[*sha]
		hasChild = hasChild && len(children) > 0
		if seen && !hasChild {
			str := fmt.Sprintf("duplicate proof-of-stake (%v) for orphan block %s", stake, sha)
			return ruleError(ErrDuplicateStake, str)
		}
		stakeSeenOrphan[stake] = true
	}
	// TODO(kac-:dup-stake)
	// there is explicit Ask for block not handled now
	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L2055
	return nil
}

func (b *BlockChain) ppcOrphanBlockRemoved(block *btcutil.Block) {
	// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L2078
	delete(stakeSeenOrphan, getProofOfStakeFromBlock(block))
}

func (b *BlockChain) ppcProcessBlock(block *btcutil.Block, phase processPhase) error {
	switch phase {
	case phasePreSanity:
		// https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.cpp#L1985
		// peercoin: check proof-of-stake
		// Limited duplicity on stake: prevents block flood attack
		// Duplicate stake allowed only when there is orphan child block
		// TODO(kac-) should it be exported to limitedStakeDuplicityCheck(block)error ?
		if block.IsProofOfStake() {
			sha := block.Hash()
			stake := getProofOfStakeFromBlock(block)
			_, seen := stakeSeen[stake]
			childs, hasChild := b.prevOrphans[*sha]
			hasChild = hasChild && (len(childs) > 0)
			if seen && !hasChild {
				str := fmt.Sprintf("duplicate proof-of-stake (%v) for orphan block %s", stake, sha)
				return ruleError(ErrDuplicateStake, str)
			}
		}
	}
	return nil
}

/* todo ppc unused -> netsync
// GetLastBlockHeader ppc: find last block from db up to lastSha
func GetLastBlockHeader(db database.Db, lastSha *chainhash.Hash, proofOfStake bool) (
	header *wire.BlockHeader, meta *wire.Meta, err error) {
	sha := lastSha
	for true {
		header, meta, err = db.FetchBlockHeaderBySha(sha)
		if err != nil {
			break
		}
		if header.PrevBlock.IsEqual(&zeroHash) {
			break
		}
		if isProofOfStake(meta) == proofOfStake {
			break
		}
		sha = &header.PrevBlock
	}
	return
}
*/

/* todo ppc -> netsync
// GetKernelStakeModifier
// This function is NOT safe for concurrent access. Use blockmanager.
func (b *BlockChain) GetKernelStakeModifier(hash *chainhash.Hash, timeSource MedianTimeSource) (uint64, error) {
	stakeModifier, _, _, err := b.getKernelStakeModifier(hash, timeSource, false)
	return stakeModifier, err
}
*/

// WantedOrphan finds block wanted by given orphan block
//
// This function is safe for concurrent access.
func (b *BlockChain) WantedOrphan(hash *chainhash.Hash) *chainhash.Hash {
	// Protect concurrent access.  Using a read lock only so multiple
	// readers can query without blocking each other.
	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	// Work back to the first block in the orphan chain
	prevHash := hash
	for {
		orphan, exists := b.orphans[*prevHash]
		if !exists {
			break
		}
		prevHash = &orphan.block.MsgBlock().Header.PrevBlock
	}

	return prevHash
}
