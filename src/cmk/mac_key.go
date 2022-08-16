package cmk

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nsmithuk/local-kms/src/service"
)

type MacKey struct {
	BaseKey
	BackingKey          []byte
	ParametersForImport ParametersForImport
}

func NewMacKey(metadata KeyMetadata, policy string, origin KeyOrigin, spec KeySpec) (*MacKey, error) {
	k := &MacKey{}

	if origin != KeyOriginExternal {
		k.BackingKey = generateMacKey(spec)
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
			return errors.New("HMAC_224 keys must be 28 bytes in length")
		}
		keyLen = 28
	case SpecHmacSHA256:
		if len(m) != 32 {
			return errors.New("HMAC_256 keys must be 32 bytes in length")
		}
		keyLen = 32
	case SpecHmacSHA384:
		if len(m) != 48 {
			return errors.New("HMAC_384 keys must be 48 bytes in length")
		}
		keyLen = 48
	case SpecHmacSHA512:
		if len(m) != 64 {
			return errors.New("HMAC_512 keys must be 64 bytes in length")
		}
		keyLen = 64
	default:
		return errors.New("invalid key spec")
	}

	key := make([]byte, keyLen)
	copy(key[:], m[:keyLen])

	// If this is the first time we're importing key material then we're all good
	if len(k.BackingKey) == 0 {
		k.BackingKey = key

	} else if !bytes.Equal(key, k.BackingKey) {
		// else if the key material doesn't match what was already imported then
		// throw and error
		return errors.New("Key material does not match existing key material")
	}

	return nil
}

//-----------------------

func generateMacKey(spec KeySpec) []byte {
	switch spec {
	case SpecHmacSHA224:
		return service.GenerateRandomData(28)
	case SpecHmacSHA256:
		return service.GenerateRandomData(32)
	case SpecHmacSHA384:
		return service.GenerateRandomData(48)
	case SpecHmacSHA512:
		return service.GenerateRandomData(64)
	}
	return nil
}

//-----------------------
// Construct key from YAML (seeding)

func (k *MacKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type YamlKey struct {
		Metadata   KeyMetadata `yaml:"Metadata"`
		BackingKey string      `yaml:"BackingKey"`
	}

	yk := YamlKey{}
	if err := unmarshal(&yk); err != nil {
		return &UnmarshalYAMLError{err.Error()}
	}

	k.Type = TypeMac
	k.Metadata = yk.Metadata
	defaultSeededKeyMetadata(&k.Metadata)

	keyBytes, err := hex.DecodeString(yk.BackingKey)
	if err != nil {
		return &UnmarshalYAMLError{fmt.Sprintf("Unable to decode hex key: %s", err)}
	}
	k.BackingKey = keyBytes

	k.Metadata.KeyUsage = UsageGenerateVerifyMac

	if k.Metadata.Origin == KeyOriginExternal && len(k.BackingKey) == 0 {
		k.Metadata.KeyState = KeyStatePendingImport
		k.Metadata.Enabled = false
	}

	return nil
}
