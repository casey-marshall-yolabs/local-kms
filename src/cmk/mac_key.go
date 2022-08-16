package cmk

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nsmithuk/local-kms/src/service"
)

type MacKey struct {
	BaseKey
	BackingKeys         [][64]byte
	NextKeyRotation     time.Time
	ParametersForImport ParametersForImport
}

func NewMacKey(metadata KeyMetadata, policy string, origin KeyOrigin, spec KeySpec) (*MacKey, error) {
	k := &MacKey{
		BackingKeys: [][64]byte{},
	}

	if origin != KeyOriginExternal {
		k.BackingKeys = append(k.BackingKeys, generateMacKey())
	}

	k.Type = TypeMac
	k.Metadata = metadata
	k.Policy = policy

	k.Metadata.KeyUsage = UsageGenerateVerifyMac
	k.Metadata.KeySpec = spec
	k.Metadata.CustomerMasterKeySpec = spec
	switch spec {
	case SpecHmacSHA224:
		k.Metadata.MacAlgorithms = []MacAlgorithm{MacAlgorithmHmacSHA224}
	case SpecHmacSHA256:
		k.Metadata.MacAlgorithms = []MacAlgorithm{MacAlgorithmHmacSHA256}
	case SpecHmacSHA384:
		k.Metadata.MacAlgorithms = []MacAlgorithm{MacAlgorithmHmacSHA384}
	case SpecHmacSHA512:
		k.Metadata.MacAlgorithms = []MacAlgorithm{MacAlgorithmHmacSHA512}
	default:
		return nil, errors.New("invalid mac key spec")
	}

	return k, nil
}

//----------------------------------------------------

func (k *MacKey) GetArn() string {
	return k.GetMetadata().Arn
}

func (k *MacKey) GetPolicy() string {
	return k.Policy
}

func (k *MacKey) GetKeyType() KeyType {
	return k.Type
}

func (k *MacKey) GetMetadata() *KeyMetadata {
	return &k.Metadata
}

//----------------------------------------------------

func (k *MacKey) GetParametersForImport() *ParametersForImport {
	return &k.ParametersForImport
}

func (k *MacKey) SetParametersForImport(p *ParametersForImport) {
	k.ParametersForImport = *p
}

func (k *MacKey) ImportKeyMaterial(m []byte) error {
	var keyLen int = 0
	switch k.Metadata.KeySpec {
	case SpecHmacSHA224:
		if len(m) != 28 {
			return errors.New("HMAC_224 keys must be 28 bytes in length.")
		}
		keyLen = 28
	case SpecHmacSHA256:
		if len(m) != 32 {
			return errors.New("HMAC_256 keys must be 32 bytes in length.")
		}
		keyLen = 32
	case SpecHmacSHA384:
		if len(m) != 48 {
			return errors.New("HMAC_384 keys must be 48 bytes in length.")
		}
		keyLen = 48
	case SpecHmacSHA512:
		if len(m) != 64 {
			return errors.New("HMAC_512 keys must be 64 bytes in length.")
		}
		keyLen = 64
	default:
		return errors.New("invalid key spec!")
	}

	var key [64]byte
	copy(key[:], m[:keyLen])

	// If this is the first time we're importing key material then we're all good
	if len(k.BackingKeys) == 0 {
		k.BackingKeys = append(k.BackingKeys, key)

	} else if key != k.BackingKeys[0] {
		// else if the key material doesn't match what was already imported then
		// throw and error
		return errors.New("Key material does not match existing key material.")
	}

	return nil
}

func (k *MacKey) RotateIfNeeded() bool {

	if !k.NextKeyRotation.IsZero() && k.NextKeyRotation.Before(time.Now()) {

		k.BackingKeys = append(k.BackingKeys, generateMacKey())

		// Reset the rotation timer
		k.NextKeyRotation = time.Now().AddDate(1, 0, 0)

		// The key did rotate
		return true
	}

	// The key did not rotate
	return false
}

//-----------------------

func generateMacKey() [64]byte {
	var key [64]byte
	copy(key[:], service.GenerateRandomData(64))
	return key
}

//-----------------------
// Construct key from YAML (seeding)

func (k *MacKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type YamlKey struct {
		Metadata        KeyMetadata `yaml:"Metadata"`
		BackingKeys     []string    `yaml:"BackingKeys"`
		NextKeyRotation time.Time   `yaml:"NextKeyRotation"`
	}

	yk := YamlKey{}
	if err := unmarshal(&yk); err != nil {
		return &UnmarshalYAMLError{err.Error()}
	}

	k.Type = TypeMac
	k.Metadata = yk.Metadata
	defaultSeededKeyMetadata(&k.Metadata)
	k.NextKeyRotation = yk.NextKeyRotation

	if k.Metadata.Origin == KeyOriginExternal {
		switch {
		case len(yk.BackingKeys) == 0:
			return nil
		case len(yk.BackingKeys) > 1:
			return &UnmarshalYAMLError{"EXTERNAL keys can only have a single backing key"}
		}
	}

	if len(yk.BackingKeys) < 1 {
		return &UnmarshalYAMLError{"At least one backing key must be supplied"}
	}

	k.BackingKeys = make([][64]byte, len(yk.BackingKeys))

	var keyLen int = 0
	switch k.Metadata.KeySpec {
	case SpecHmacSHA224:
		keyLen = 28
	case SpecHmacSHA256:
		keyLen = 32
	case SpecHmacSHA384:
		keyLen = 48
	case SpecHmacSHA512:
		keyLen = 64
	default:
		return &UnmarshalYAMLError{"Invalid key spec for HMAC key"}
	}

	for i, keyStr := range yk.BackingKeys {

		keyBytes, err := hex.DecodeString(keyStr)
		if err != nil {
			return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode hex key: %s", err)}
		}

		if len(keyBytes) != keyLen {
			return &UnmarshalYAMLError{
				fmt.Sprintf(
					"Backing key must be hex encoded and exactly %d bytes (%d bit). %d bytes found",
					keyLen, keyLen*8, len(keyBytes)),
			}
		}

		copy(k.BackingKeys[i][:keyLen], keyBytes[:])
	}

	k.Metadata.KeyUsage = UsageGenerateVerifyMac

	if k.Metadata.Origin == KeyOriginExternal && len(k.BackingKeys) == 0 {
		k.Metadata.KeyState = KeyStatePendingImport
		k.Metadata.Enabled = false
	}

	return nil
}
