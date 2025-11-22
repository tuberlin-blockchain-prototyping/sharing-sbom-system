package service

import (
	"encoding/json"
	"fmt"

	"go.etcd.io/bbolt"
)

var bucketName = []byte("smts")

type Storage struct {
	db *bbolt.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		return nil, err
	}

	return &Storage{db: db}, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) StoreSMT(rootHash string, smtData json.RawMessage) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.Put([]byte(rootHash), smtData)
	})
}

func (s *Storage) GetSMT(rootHash string) (json.RawMessage, error) {
	var data []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		v := b.Get([]byte(rootHash))
		if v == nil {
			return fmt.Errorf("SMT not found for root: %s", rootHash)
		}
		data = make([]byte, len(v))
		copy(data, v)
		return nil
	})
	return json.RawMessage(data), err
}

