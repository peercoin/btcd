// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"crypto/rand"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
)

// TestMerkleBlock tests the MsgMerkleBlock API.
func TestMerkleBlock(t *testing.T) {
	pver := ProtocolVersion
	enc := BaseEncoding

	// Block 1 header.
	prevHash := &blockOne.Header.PrevBlock
	merkleHash := &blockOne.Header.MerkleRoot
	bits := blockOne.Header.Bits
	nonce := blockOne.Header.Nonce
	flags := blockOne.Header.Flags
	bh := NewBlockHeader(1, prevHash, merkleHash, bits, nonce, flags)

	// Ensure the command is expected value.
	wantCmd := "merkleblock"
	msg := NewMsgMerkleBlock(bh)
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgBlock: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	// Num addresses (varInt) + max allowed addresses.
	wantPayload := uint32(4000000)
	maxPayload := msg.MaxPayloadLength(pver)
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Load maxTxPerBlock hashes
	data := make([]byte, 32)
	for i := 0; i < maxTxPerBlock; i++ {
		rand.Read(data)
		hash, err := chainhash.NewHash(data)
		if err != nil {
			t.Errorf("NewHash failed: %v\n", err)
			return
		}

		if err = msg.AddTxHash(hash); err != nil {
			t.Errorf("AddTxHash failed: %v\n", err)
			return
		}
	}

	// Add one more Tx to test failure.
	rand.Read(data)
	hash, err := chainhash.NewHash(data)
	if err != nil {
		t.Errorf("NewHash failed: %v\n", err)
		return
	}

	if err = msg.AddTxHash(hash); err == nil {
		t.Errorf("AddTxHash succeeded when it should have failed")
		return
	}

	// Test encode with latest protocol version.
	var buf bytes.Buffer
	err = msg.BtcEncode(&buf, pver, enc)
	if err != nil {
		t.Errorf("encode of MsgMerkleBlock failed %v err <%v>", msg, err)
	}

	// Test decode with latest protocol version.
	readmsg := MsgMerkleBlock{}
	err = readmsg.BtcDecode(&buf, pver, enc)
	if err != nil {
		t.Errorf("decode of MsgMerkleBlock failed [%v] err <%v>", buf, err)
	}

	// Force extra hash to test maxTxPerBlock.
	msg.Hashes = append(msg.Hashes, hash)
	err = msg.BtcEncode(&buf, pver, enc)
	if err == nil {
		t.Errorf("encode of MsgMerkleBlock succeeded with too many " +
			"tx hashes when it should have failed")
		return
	}

	// Force too many flag bytes to test maxFlagsPerMerkleBlock.
	// Reset the number of hashes back to a valid value.
	msg.Hashes = msg.Hashes[len(msg.Hashes)-1:]
	msg.Flags = make([]byte, maxFlagsPerMerkleBlock+1)
	err = msg.BtcEncode(&buf, pver, enc)
	if err == nil {
		t.Errorf("encode of MsgMerkleBlock succeeded with too many " +
			"flag bytes when it should have failed")
		return
	}
}

// TestMerkleBlockCrossProtocol tests the MsgMerkleBlock API when encoding with
// the latest protocol version and decoding with BIP0031Version.
func TestMerkleBlockCrossProtocol(t *testing.T) {
	// Block 1 header.
	prevHash := &blockOne.Header.PrevBlock
	merkleHash := &blockOne.Header.MerkleRoot
	bits := blockOne.Header.Bits
	nonce := blockOne.Header.Nonce
	flags := blockOne.Header.Flags
	bh := NewBlockHeader(1, prevHash, merkleHash, bits, nonce, flags)

	msg := NewMsgMerkleBlock(bh)

	// Encode with latest protocol version.
	var buf bytes.Buffer
	err := msg.BtcEncode(&buf, ProtocolVersion, BaseEncoding)
	if err != nil {
		t.Errorf("encode of NewMsgFilterLoad failed %v err <%v>", msg,
			err)
	}

	// Decode with old protocol version.
	var readmsg MsgFilterLoad
	err = readmsg.BtcDecode(&buf, BIP0031Version, BaseEncoding)
	if err == nil {
		t.Errorf("decode of MsgFilterLoad succeeded when it shouldn't have %v",
			msg)
	}
}

// TestMerkleBlockWire tests the MsgMerkleBlock wire encode and decode for
// various numbers of transaction hashes and protocol versions.
func TestMerkleBlockWire(t *testing.T) {
	tests := []struct {
		in   *MsgMerkleBlock // Message to encode
		out  *MsgMerkleBlock // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version.
		{
			&merkleBlockOne, &merkleBlockOne, merkleBlockOneBytes,
			ProtocolVersion, BaseEncoding,
		},

		// Protocol version BIP0037Version.
		{
			&merkleBlockOne, &merkleBlockOne, merkleBlockOneBytes,
			BIP0037Version, BaseEncoding,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BtcEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgMerkleBlock
		rbuf := bytes.NewReader(test.buf)
		err = msg.BtcDecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("BtcDecode #%d\n got: %s want: %s", i,
				spew.Sdump(&msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestMerkleBlockWireErrors performs negative tests against wire encode and
// decode of MsgBlock to confirm error paths work correctly.
func TestMerkleBlockWireErrors(t *testing.T) {
	// Use protocol version 70001 specifically here instead of the latest
	// because the test data is using bytes encoded with that protocol
	// version.
	pver := uint32(70001)
	pverNoMerkleBlock := BIP0037Version - 1
	wireErr := &MessageError{}

	tests := []struct {
		in       *MsgMerkleBlock // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Force error in version.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 0,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in prev block hash.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 4,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in merkle root.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 36,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in timestamp.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 68,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in difficulty bits.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 72,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in header nonce.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 76,
			io.ErrShortWrite, io.EOF,
		},
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 80,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in transaction count.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 84,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in num hashes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 88,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in hashes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 89,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in num flag bytes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 121,
			io.ErrShortWrite, io.EOF,
		},
		// Force error in flag bytes.
		{
			&merkleBlockOne, merkleBlockOneBytes, pver, BaseEncoding, 122,
			io.ErrShortWrite, io.EOF,
		},
		// Force error due to unsupported protocol version.
		{
			&merkleBlockOne, merkleBlockOneBytes, pverNoMerkleBlock,
			BaseEncoding, 123, wireErr, wireErr,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := test.in.BtcEncode(w, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.writeErr) {
			t.Errorf("BtcEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if _, ok := err.(*MessageError); !ok {
			if err != test.writeErr {
				t.Errorf("BtcEncode #%d wrong error got: %v, "+
					"want: %v", i, err, test.writeErr)
				continue
			}
		}

		// Decode from wire format.
		var msg MsgMerkleBlock
		r := newFixedReader(test.max, test.buf)
		err = msg.BtcDecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if _, ok := err.(*MessageError); !ok {
			if err != test.readErr {
				t.Errorf("BtcDecode #%d wrong error got: %v, "+
					"want: %v", i, err, test.readErr)
				continue
			}
		}
	}
}

// TestMerkleBlockOverflowErrors performs tests to ensure encoding and decoding
// merkle blocks that are intentionally crafted to use large values for the
// number of hashes and flags are handled properly.  This could otherwise
// potentially be used as an attack vector.
func TestMerkleBlockOverflowErrors(t *testing.T) {
	// Use protocol version 70001 specifically here instead of the latest
	// protocol version because the test data is using bytes encoded with
	// that version.
	pver := uint32(70001)

	// Create bytes for a merkle block that claims to have more than the max
	// allowed tx hashes.
	var buf bytes.Buffer
	WriteVarInt(&buf, pver, maxTxPerBlock+1)
	numHashesOffset := 88 // todo ppc
	exceedMaxHashes := make([]byte, numHashesOffset)
	copy(exceedMaxHashes, merkleBlockOneBytes[:numHashesOffset])
	exceedMaxHashes = append(exceedMaxHashes, buf.Bytes()...)

	// Create bytes for a merkle block that claims to have more than the max
	// allowed flag bytes.
	buf.Reset()
	WriteVarInt(&buf, pver, maxFlagsPerMerkleBlock+1)
	numFlagBytesOffset := 121 // todo ppc
	exceedMaxFlagBytes := make([]byte, numFlagBytesOffset)
	copy(exceedMaxFlagBytes, merkleBlockOneBytes[:numFlagBytesOffset])
	exceedMaxFlagBytes = append(exceedMaxFlagBytes, buf.Bytes()...)

	tests := []struct {
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
		err  error           // Expected error
	}{
		// Block that claims to have more than max allowed hashes.
		{exceedMaxHashes, pver, BaseEncoding, &MessageError{}},
		// Block that claims to have more than max allowed flag bytes.
		{exceedMaxFlagBytes, pver, BaseEncoding, &MessageError{}},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode from wire format.
		var msg MsgMerkleBlock
		r := bytes.NewReader(test.buf)
		err := msg.BtcDecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}
	}
}

// merkleBlockOne is a merkle block created from block one of the block chain
// where the first transaction matches.
var merkleBlockOne = MsgMerkleBlock{
	Header: BlockHeader{
		Version: 1,
		PrevBlock: chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
			0xe3, 0x27, 0xcd, 0x80, 0xc8, 0xb1, 0x7e, 0xfd,
			0xa4, 0xea, 0x08, 0xc5, 0x87, 0x7e, 0x95, 0xd8,
			0x77, 0x46, 0x2a, 0xb6, 0x63, 0x49, 0xd5, 0x66,
			0x71, 0x67, 0xfe, 0x32, 0x00, 0x00, 0x00, 0x00,
		}),
		MerkleRoot: chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
			0x68, 0xf6, 0x23, 0xd2, 0x06, 0xa1, 0xbd, 0xe3,
			0xb0, 0x38, 0x2e, 0x97, 0xaf, 0x9c, 0x0b, 0x6b,
			0xfa, 0x70, 0x8c, 0xa4, 0xc2, 0x5f, 0x33, 0x99,
			0x53, 0xe1, 0x34, 0xff, 0x4e, 0xe8, 0xda, 0x1b,
		}),
		Timestamp: time.Unix(0x50312e24, 0), // Sun Aug 19 2012 20:19:16 GMT+0200
		Bits:      0x1c00ffff,
		Nonce:     0x722a498e, // 1915373966
		Flags:     0x00000000,
	},
	Transactions: 1,
	Hashes: []*chainhash.Hash{
		(*chainhash.Hash)(&[chainhash.HashSize]byte{ // Make go vet happy.
			0x68, 0xf6, 0x23, 0xd2, 0x06, 0xa1, 0xbd, 0xe3,
			0xb0, 0x38, 0x2e, 0x97, 0xaf, 0x9c, 0x0b, 0x6b,
			0xfa, 0x70, 0x8c, 0xa4, 0xc2, 0x5f, 0x33, 0x99,
			0x53, 0xe1, 0x34, 0xff, 0x4e, 0xe8, 0xda, 0x1b,
		}),
	},
	Flags: []byte{0x80},
}

// merkleBlockOneBytes is the serialized bytes for a merkle block created from
// block one of the block chain where the first transaction matches.
var merkleBlockOneBytes = []byte{
	0x01, 0x00, 0x00, 0x00, // Version 1
	0xe3, 0x27, 0xcd, 0x80, 0xc8, 0xb1, 0x7e, 0xfd,
	0xa4, 0xea, 0x08, 0xc5, 0x87, 0x7e, 0x95, 0xd8,
	0x77, 0x46, 0x2a, 0xb6, 0x63, 0x49, 0xd5, 0x66,
	0x71, 0x67, 0xfe, 0x32, 0x00, 0x00, 0x00, 0x00, // PrevBlock
	0x68, 0xf6, 0x23, 0xd2, 0x06, 0xa1, 0xbd, 0xe3,
	0xb0, 0x38, 0x2e, 0x97, 0xaf, 0x9c, 0x0b, 0x6b,
	0xfa, 0x70, 0x8c, 0xa4, 0xc2, 0x5f, 0x33, 0x99,
	0x53, 0xe1, 0x34, 0xff, 0x4e, 0xe8, 0xda, 0x1b, // MerkleRoot
	0x24, 0x2e, 0x31, 0x50, // Timestamp
	0xff, 0xff, 0x00, 0x1c, // Bits
	0x8e, 0x49, 0x2a, 0x72, // Nonce
	0x00, 0x00, 0x00, 0x00, // Flags
	0x01, 0x00, 0x00, 0x00, // TxnCount
	0x01, // Num hashes
	0x68, 0xf6, 0x23, 0xd2, 0x06, 0xa1, 0xbd, 0xe3,
	0xb0, 0x38, 0x2e, 0x97, 0xaf, 0x9c, 0x0b, 0x6b,
	0xfa, 0x70, 0x8c, 0xa4, 0xc2, 0x5f, 0x33, 0x99,
	0x53, 0xe1, 0x34, 0xff, 0x4e, 0xe8, 0xda, 0x1b, // Hash
	0x01, // Num flag bytes
	0x80, // Flags
}
