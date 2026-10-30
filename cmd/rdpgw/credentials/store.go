// Package credentials stores revocable gateway bearer credentials. Only hashes
// of bearer values are persisted. A database is owned by one gateway process.
package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	bolt "go.etcd.io/bbolt"
)

const MaxLifetime = 30 * 24 * time.Hour
const tokenPrefix = "c1_"

var ErrInvalid = errors.New("credential is unknown, expired or revoked")
var recordsBucket = []byte("credentials-v1")
var usersBucket = []byte("user-generations-v1")
var settingsBucket = []byte("settings-v1")

type Record struct {
	ID         string        `json:"id"`
	Subject    string        `json:"subject"`
	UserName   string        `json:"user"`
	Host       string        `json:"host"`
	ClientIP   string        `json:"clientIp"`
	Policy     access.Policy `json:"policy"`
	AuthTime   time.Time     `json:"authTime"`
	IssuedAt   time.Time     `json:"issuedAt"`
	ExpiresAt  time.Time     `json:"expiresAt"`
	Generation uint64        `json:"-"`
	Revoked    bool          `json:"revoked"`
}

// storedRecord keeps the generation out of public API responses.
type storedRecord struct {
	Record
	UserGeneration uint64 `json:"generation"`
}

type Store struct {
	db  *bolt.DB
	now func() time.Time
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: time.Now}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{recordsBucket, usersBucket, settingsBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// BindIssuer prevents accidentally trusting records from a different realm.
func (s *Store) BindIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("empty credential issuer")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(settingsBucket)
		if v := b.Get([]byte("issuer")); v != nil && string(v) != issuer {
			return errors.New("credential database belongs to another OIDC issuer")
		}
		return b.Put([]byte("issuer"), []byte(issuer))
	})
}

func generation(tx *bolt.Tx, subject string) uint64 {
	v := tx.Bucket(usersBucket).Get([]byte(subject))
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func (s *Store) Generation(subject string) (uint64, error) {
	var g uint64
	err := s.db.View(func(tx *bolt.Tx) error { g = generation(tx, subject); return nil })
	return g, err
}

func tokenID(token string) (string, error) {
	if len(token) != len(tokenPrefix)+43 || token[:len(tokenPrefix)] != tokenPrefix {
		return "", ErrInvalid
	}
	if _, err := base64.RawURLEncoding.DecodeString(token[len(tokenPrefix):]); err != nil {
		return "", ErrInvalid
	}
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:]), nil
}

func (s *Store) Issue(r Record) (string, error) {
	now := s.now()
	if r.Subject == "" || r.UserName == "" || r.Host == "" || r.AuthTime.IsZero() ||
		r.AuthTime.After(now.Add(time.Minute)) || !r.ExpiresAt.After(now) ||
		r.ExpiresAt.After(r.AuthTime.Add(MaxLifetime)) {
		return "", ErrInvalid
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	token := tokenPrefix + base64.RawURLEncoding.EncodeToString(secret[:])
	r.ID, _ = tokenID(token)
	r.IssuedAt, r.Revoked = now, false
	data, err := json.Marshal(storedRecord{Record: r, UserGeneration: r.Generation})
	if err != nil {
		return "", err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if generation(tx, r.Subject) != r.Generation {
			return ErrInvalid
		}
		return tx.Bucket(recordsBucket).Put([]byte(r.ID), data)
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func loadRecord(tx *bolt.Tx, id string) (Record, error) {
	var stored storedRecord
	v := tx.Bucket(recordsBucket).Get([]byte(id))
	if v == nil {
		return Record{}, ErrInvalid
	}
	if err := json.Unmarshal(v, &stored); err != nil {
		return Record{}, err
	}
	r := stored.Record
	r.Generation = stored.UserGeneration
	if r.ID != id || r.Subject == "" || r.UserName == "" || r.Host == "" {
		return Record{}, ErrInvalid
	}
	r.Revoked = r.Revoked || generation(tx, r.Subject) != r.Generation
	return r, nil
}

func (s *Store) Lookup(token string) (Record, error) {
	id, err := tokenID(token)
	if err != nil {
		return Record{}, err
	}
	return s.Get(id)
}

func (s *Store) Get(id string) (Record, error) {
	var r Record
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		r, err = loadRecord(tx, id)
		if err != nil {
			return err
		}
		if r.Revoked || !s.now().Before(r.ExpiresAt) || r.AuthTime.IsZero() || r.ExpiresAt.After(r.AuthTime.Add(MaxLifetime)) {
			return ErrInvalid
		}
		return nil
	})
	return r, err
}

func (s *Store) List(subject string) ([]Record, error) {
	result := []Record{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(recordsBucket).ForEach(func(k, v []byte) error {
			r, err := loadRecord(tx, string(k))
			if err != nil {
				return err
			}
			if subject == "" || r.Subject == subject {
				result = append(result, r)
			}
			return nil
		})
	})
	return result, err
}

func (s *Store) Revoke(id, owner string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		r, err := loadRecord(tx, id)
		if err != nil {
			return err
		}
		if owner != "" && r.Subject != owner {
			return ErrInvalid
		}
		r.Revoked = true
		data, err := json.Marshal(storedRecord{Record: r, UserGeneration: r.Generation})
		if err != nil {
			return err
		}
		return tx.Bucket(recordsBucket).Put([]byte(id), data)
	})
}

func (s *Store) RevokeUser(subject string) error {
	if subject == "" {
		return ErrInvalid
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		g := generation(tx, subject)
		if g == ^uint64(0) {
			return errors.New("credential generation exhausted")
		}
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], g+1)
		return tx.Bucket(usersBucket).Put([]byte(subject), v[:])
	})
}
