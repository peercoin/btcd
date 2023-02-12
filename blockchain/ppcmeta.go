// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
)

var blockMetaSuffix = []byte{'b', 'm'}

// todo ppc verify
//  have a peek at blockchain/indexers/cfindex to optimise

func hashMetaToKey(hash *chainhash.Hash) []byte {
	key := make([]byte, len(hash)+len(blockMetaSuffix))
	copy(key, hash[:])
	copy(key[len(hash):], blockMetaSuffix)
	return key
}

func GetBlkMeta(dbTx database.Tx, hash chainhash.Hash) (rbuf []byte, err error) {
	key := hashMetaToKey(&hash)
	bucket := dbTx.Metadata().Bucket(blockMetaBucketName)
	rbuf = bucket.Get(key)
	if rbuf == nil {
		// todo ppc re-check error creation
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("failed to find meta for %v ",
				hash),
		}
	}
	return
}

func setBlkMeta(dbTx database.Tx, hash *chainhash.Hash, buf []byte) error {
	key := hashMetaToKey(hash)
	bucket := dbTx.Metadata().Bucket(blockMetaBucketName)
	err := bucket.Put(key, buf[:])
	return err
}