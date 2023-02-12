// Copyright (c) 2014-2014 PPCD developers.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	"bytes"
	"github.com/btcsuite/btcd/wire"
)

// TxOffsetUnknown is the value returned for a transaction offset that is unknown.
// This is typically because the transaction has not been inserted into a block
// yet.
const TxOffsetUnknown = uint32(0)

// KernelStakeModifierUnknown is the value returned for a block kernel stake
// modifier that is unknown.
// This is typically because the block has not been used for minting yet.
const KernelStakeModifierUnknown = uint64(0)

// Offset returns the saved offset of the transaction within a block.  This value
// will be TxOffsetUnknown if it hasn't already explicitly been set.
func (t *Tx) Offset() uint32 {
	return t.txOffset
}

// SetOffset sets the offset of the transaction in within a block.
func (t *Tx) SetOffset(offset uint32) {
	t.txOffset = offset
}

func (block *Block) Meta() *wire.Meta {
	if block.meta != nil {
		return block.meta
	}
	block.meta = new(wire.Meta)
	return block.meta
}

// MetaToBytes serializes block meta data to byte array
func (block *Block) MetaToBytes() ([]byte, error) {
	// todo ppc we want this functional and ideally not bound to block
	//   ideally it would be usable on chain init
	// Return the cached serialized bytes if it has already been generated.
	if len(block.serializedMeta) != 0 {
		return block.serializedMeta, nil
	}

	serializedMeta, err := MetaToBytes(block.Meta())
	if err != nil {
		return nil, nil
	}

	// Cache the serialized bytes and return them.
	block.serializedMeta = serializedMeta
	return serializedMeta, nil
}

// MetaFromBytes deserializes block meta data from byte array
func (block *Block) MetaFromBytes(serializedMeta []byte) error {
	mr := bytes.NewReader(serializedMeta)
	err := block.Meta().Deserialize(mr)
	if err != nil {
		return err
	}
	block.serializedMeta = serializedMeta
	return nil
}

// todo ppc refactor
func MetaToBytes(meta *wire.Meta) ([]byte, error) {
	var w bytes.Buffer
	err := meta.Serialize(&w)
	if err != nil {
		return nil, err
	}
	serializedMeta := w.Bytes()
	return serializedMeta, nil
}

// todo ppc refactor
func MetaFromBytes(serializedMeta []byte) (*wire.Meta, error) {
	mr := bytes.NewReader(serializedMeta)
	meta := new(wire.Meta)
	err := meta.Deserialize(mr)
	if err != nil {
		return nil, err
	}
	return meta, nil
}

// NewBlockWithMetas NewBlock returns a new instance of a bitcoin block given an underlying
// wire.MsgBlock.  See Block.
func NewBlockWithMetas(msgBlock *wire.MsgBlock, meta *wire.Meta) *Block {
	return &Block{
		msgBlock:    msgBlock,
		blockHeight: BlockHeightUnknown,
		meta:        meta,
	}
}

// IsProofOfStake https://github.com/ppcoin/ppcoin/blob/v0.4.0ppc/src/main.h#L962
// peercoin: two types of block: proof-of-work or proof-of-stake
func (block *Block) IsProofOfStake() bool {
	return block.msgBlock.IsProofOfStake()
}