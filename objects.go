// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package openpgp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"time"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

type KDF struct {
	Algorithm      AlgKDF
	HashAlgorithm  AlgHash
	Iterations     int
	SaltPW1        [8]byte
	SaltPW3        [8]byte
	SaltRC         [8]byte
	InitialHashPW1 []byte
	InitialHashPW3 []byte
}

func (k *KDF) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case 0x81:
			if len(tv.Value) != 1 {
				return ErrInvalidLength
			}

			k.Algorithm = AlgKDF(tv.Value[0])

		case 0x82:
			if len(tv.Value) != 1 {
				return ErrInvalidLength
			}

			k.HashAlgorithm = AlgHash(tv.Value[0])

		case 0x83:
			if len(tv.Value) != 4 {
				return ErrInvalidLength
			}

			k.Iterations = int(binary.BigEndian.Uint32(tv.Value))

		case 0x84:
			if len(tv.Value) != 8 {
				return ErrInvalidLength
			}

			k.SaltPW1 = [8]byte(tv.Value)

		case 0x85:
			if len(tv.Value) != 8 {
				return ErrInvalidLength
			}

			k.SaltRC = [8]byte(tv.Value)

		case 0x86:
			if len(tv.Value) != 8 {
				return ErrInvalidLength
			}

			k.SaltPW3 = [8]byte(tv.Value)

		case 0x87:
			k.InitialHashPW1 = tv.Value

		case 0x88:
			k.InitialHashPW3 = tv.Value

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "kdf"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

func (k *KDF) Encode() ([]byte, error) {
	parts := []tlv.TagValue{
		tlv.New(0x81, byte(k.Algorithm)),
	}

	switch k.Algorithm {
	case AlgKDFNone:

	case AlgKDFIterSaltedS2K:
		parts = append(parts,
			tlv.New(0x82, byte(k.HashAlgorithm)),
			tlv.New(0x83, uint32(k.Iterations)),
			tlv.New(0x84, k.SaltPW1[:]),
			tlv.New(0x85, k.SaltRC[:]),
			tlv.New(0x86, k.SaltPW3[:]),
			tlv.New(0x87, k.InitialHashPW1),
			tlv.New(0x88, k.InitialHashPW3),
		)

	default:
		return nil, errUnsupported
	}

	return tlv.EncodeBER(parts...)
}

type UserInteractionFlag struct {
	Mode    UserInteractionMode
	Feature byte
}

func (uif *UserInteractionFlag) Decode(b []byte) error {
	if len(b) != 2 {
		return ErrInvalidLength
	}

	uif.Mode = UserInteractionMode(b[0])
	uif.Feature = b[1]

	return nil
}

type ImportFormat byte

const (
	ImportFormatRSAStd ImportFormat = iota
	ImportFormatRSAStdWithModulus
	ImportFormatRSACRT
	ImportFormatRSACRTWithModulus

	ImportFormatECDSAStdWithPublicKey ImportFormat = 0xff
)

type AlgorithmAttributes struct {
	Algorithm AlgPubkey

	// Relevant for RSA
	LengthModulus  uint16
	LengthExponent uint16

	// Relevant for ECDSA/ECDH
	OID []byte

	ImportFormat ImportFormat
}

func (a AlgorithmAttributes) Equal(ab AlgorithmAttributes) bool {
	return reflect.DeepEqual(a, ab)
}

func (a *AlgorithmAttributes) Decode(b []byte) error {
	if len(b) < 1 {
		return ErrInvalidLength
	}

	a.Algorithm = AlgPubkey(b[0])

	switch a.Algorithm {
	case AlgPubkeyRSA:
		if len(b) < 6 {
			return ErrInvalidLength
		}

		a.LengthModulus = binary.BigEndian.Uint16(b[1:])
		a.LengthExponent = binary.BigEndian.Uint16(b[3:])
		a.ImportFormat = ImportFormat(b[5])

	case AlgPubkeyECDH, AlgPubkeyECDSA, AlgPubkeyEdDSA:
		a.OID = b[1:]

		// Strip trailing import format byte if present
		l := len(a.OID)
		if ImportFormat(a.OID[l-1]) == ImportFormatECDSAStdWithPublicKey {
			a.ImportFormat = ImportFormatECDSAStdWithPublicKey
			a.OID = a.OID[:l-1]
		}

	default:
		return errUnmarshal
	}

	return nil
}

func (a AlgorithmAttributes) Encode() (b []byte) {
	b = []byte{byte(a.Algorithm)}

	switch a.Algorithm {
	case AlgPubkeyRSA:
		b = binary.BigEndian.AppendUint16(b, a.LengthModulus)
		b = binary.BigEndian.AppendUint16(b, a.LengthExponent)
		b = append(b, byte(a.ImportFormat))

	case AlgPubkeyECDH, AlgPubkeyECDSA, AlgPubkeyEdDSA:
		b = append(b, a.OID...)
		if a.ImportFormat == ImportFormatECDSAStdWithPublicKey {
			b = append(b, byte(ImportFormatECDSAStdWithPublicKey))
		}

	default:
	}

	return b
}

func (a AlgorithmAttributes) String() string {
	switch a.Algorithm {
	case AlgPubkeyRSAEncOnly, AlgPubkeyRSASignOnly, AlgPubkeyRSA:
		return fmt.Sprintf("RSA-%d", a.LengthModulus)

	case AlgPubkeyECDH, AlgPubkeyECDSA, AlgPubkeyEdDSA:
		return a.Curve().String()

	default:
		return "<unknown>"
	}
}

func (a AlgorithmAttributes) Curve() Curve {
	for curve, oid := range oidByCurve {
		if bytes.Equal(a.OID, oid) {
			return curve
		}
	}

	return CurveUnknown
}

type Fingerprint [20]byte

type Status byte

const (
	StatusKeyNotPresent Status = iota // Not generated or imported
	StatusKeyGenerated                // On the the card
	StatusKeyImported                 // Into the card (insecure)
)

type KeyInfo struct {
	Reference      byte
	Status         Status
	AlgAttrs       AlgorithmAttributes
	Fingerprint    []byte
	FingerprintCA  []byte
	GenerationTime time.Time
	UIF            UserInteractionFlag
}

type ApplicationRelated struct {
	AID             ApplicationIdentifier
	HistoricalBytes iso.HistoricalBytes

	LengthInfo     ExtendedLengthInfo
	Capabilities   ExtendedCapabilities
	Features       GeneralFeatures
	PasswordStatus PasswordStatus

	Keys [4]KeyInfo
}

func (ar *ApplicationRelated) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	_, tvs, ok := tvs.Get(tagApplicationRelated)
	if !ok {
		return errMissingTag
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagAID:
			if err := ar.AID.Decode(tv.Value); err != nil {
				return fmt.Errorf("failed to decode application identifier: %w", err)
			}

		case tagHistoricalBytes:
			if err := ar.HistoricalBytes.Decode(tv.Value); err != nil {
				return fmt.Errorf("failed to decode historical bytes: %w", err)
			}

		case tagGeneralFeatureManagement:
			if err := ar.Features.Decode(tv.Value); err != nil {
				return fmt.Errorf("failed to decode general features: %w", err)
			}

		case tagDiscretionaryDOs:
			for _, tv := range tv.Children {
				switch tv.Tag {
				case tagExtendedLengthInfo:
					if err := ar.LengthInfo.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode extended length information: %w", err)
					}

				case tagExtendedCapabilities:
					if err := ar.Capabilities.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode extended capabilities: %w", err)
					}

				case tagAlgAttrsSign:
					if err := ar.Keys[SlotSign].AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode sign key attrs: %w", err)
					}
				case tagAlgAttrsDecrypt:
					if err := ar.Keys[SlotDecrypt].AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode decrypt key attrs: %w", err)
					}
				case tagAlgAttrsAuthn:
					if err := ar.Keys[SlotAuthn].AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode authentication key attrs: %w", err)
					}

				case tagAlgAttrsAttest:
					if err := ar.Keys[SlotAttest].AlgAttrs.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode attestation key attrs: %w", err)
					}

				case tagUIFSign:
					if err := ar.Keys[SlotSign].UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFAuthn:
					if err := ar.Keys[SlotAuthn].UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFDecrypt:
					if err := ar.Keys[SlotDecrypt].UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagUIFAttest:
					if err := ar.Keys[SlotAttest].UIF.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode user interaction flag: %w", err)
					}

				case tagPasswordStatus:
					if err := ar.PasswordStatus.Decode(tv.Value); err != nil {
						return fmt.Errorf("failed to decode password status: %w", err)
					}

				case tagFpr:
					if len(tv.Value) < 60 {
						return ErrInvalidLength
					}

					ar.Keys[SlotSign].Fingerprint = tv.Value[0:20]
					ar.Keys[SlotDecrypt].Fingerprint = tv.Value[20:40]
					ar.Keys[SlotAuthn].Fingerprint = tv.Value[40:60]

				case tagFprAttest:
					if len(tv.Value) < 20 {
						return ErrInvalidLength
					}

					ar.Keys[SlotAttest].Fingerprint = tv.Value[0:20]

				case tagFprCA:
					if len(tv.Value) < 60 {
						return ErrInvalidLength
					}

					ar.Keys[SlotSign].FingerprintCA = tv.Value[0:20]
					ar.Keys[SlotDecrypt].FingerprintCA = tv.Value[20:40]
					ar.Keys[SlotAuthn].FingerprintCA = tv.Value[40:60]

				case tagFprCAAttest:
					if len(tv.Value) < 20 {
						return ErrInvalidLength
					}

					ar.Keys[SlotAttest].FingerprintCA = tv.Value[0:20]

				case tagGenTime:
					if len(tv.Value) < 12 {
						return ErrInvalidLength
					}

					ar.Keys[SlotSign].GenerationTime = decodeTime(tv.Value[0:])
					ar.Keys[SlotDecrypt].GenerationTime = decodeTime(tv.Value[4:])
					ar.Keys[SlotAuthn].GenerationTime = decodeTime(tv.Value[8:])

				case tagGenTimeAttest:
					if len(tv.Value) < 4 {
						return ErrInvalidLength
					}

					ar.Keys[SlotAttest].GenerationTime = decodeTime(tv.Value[0:])

				case tagKeyInfo:
					for i := 0; i < len(tv.Value)/2; i++ {
						ar.Keys[i].Reference = tv.Value[i*2+0]
						ar.Keys[i].Status = Status(tv.Value[i*2+1])
					}

				default:
					slog.Warn("Received unknown tag",
						slog.String("do", "discretionary objects"),
						slog.Any("tag", tv.Tag),
						slog.String("value", hex.EncodeToString(tv.Value)))
				}
			}

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "application related"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

type PasswordStatus struct {
	ValidityPW1 uint8

	LengthPW1 uint8
	LengthRC  uint8
	LengthPW3 uint8

	AttemptsPW1 uint8
	AttemptsRC  uint8
	AttemptsPW3 uint8
}

func (ps *PasswordStatus) Decode(b []byte) error {
	if len(b) != 7 {
		return ErrInvalidLength
	}

	ps.ValidityPW1 = b[0]
	ps.LengthPW1 = b[1]
	ps.LengthRC = b[2]
	ps.LengthPW3 = b[3]
	ps.AttemptsPW1 = b[4]
	ps.AttemptsRC = b[5]
	ps.AttemptsPW3 = b[6]

	return nil
}

type ExtendedCapabilities struct {
	Flags                ExtendedCapabilitiesFlag
	AlgSM                byte
	MaxLenChallenge      uint16
	MaxLenCardholderCert uint16
	MaxLenSpecialDO      uint16
	Pin2BlockFormat      byte
	CommandMSE           byte
}

type ExtendedCapabilitiesFlag byte

const (
	CapKDF ExtendedCapabilitiesFlag = (1 << iota)
	CapAES
	CapAlgAttrsChangeable
	CapPrivateDO
	CapPasswordStatusChangeable
	CapKeyImport
	CapGetChallenge
	CapSecureMessaging
)

func (ec *ExtendedCapabilities) Decode(b []byte) error {
	if len(b) != 10 {
		return ErrInvalidLength
	}

	ec.Flags = ExtendedCapabilitiesFlag(b[0])
	ec.AlgSM = b[1]
	ec.MaxLenChallenge = binary.BigEndian.Uint16(b[2:])
	ec.MaxLenCardholderCert = binary.BigEndian.Uint16(b[4:])
	ec.MaxLenSpecialDO = binary.BigEndian.Uint16(b[6:])
	ec.Pin2BlockFormat = b[8]
	ec.CommandMSE = b[9]

	return nil
}

type Cardholder struct {
	Name     string
	Language string
	Sex      Sex
}

func (ch *Cardholder) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	_, tvs, ok := tvs.Get(tagCardholderRelated)
	if !ok {
		return errMissingTag
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagName:
			ch.Name = string(tv.Value)
		case tagSex:
			if len(tv.Value) < 1 {
				return ErrInvalidLength
			}
			ch.Sex = Sex(tv.Value[0])
		case tagLanguage:
			ch.Language = string(tv.Value)
		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "cardholder related"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

type SecuritySupportTemplate struct {
	SignatureCounter int
	CardHolderCerts  [3][]byte
}

func (sst *SecuritySupportTemplate) Decode(b []byte) (err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return err
	}

	_, tvs, ok := tvs.Get(tagSecuritySupportTemplate)
	if !ok {
		return errMissingTag
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagDSCounter:
			buf := append([]byte{0}, tv.Value...)
			sst.SignatureCounter = int(binary.BigEndian.Uint32(buf))

		case tagCerts:
			log.Println(hex.EncodeToString(tv.Value))

		default:
			slog.Warn("Received unknown tag",
				slog.String("do", "security support template"),
				slog.Any("tag", tv.Tag),
				slog.String("value", hex.EncodeToString(tv.Value)))
		}
	}

	return nil
}

type GeneralFeatures byte

const (
	GeneralFeatureTouchscreen byte = (1 << iota)
	GeneralFeatureMicrophone
	GeneralFeatureSpeaker
	GeneralFeatureLED
	GeneralFeatureKeyPad
	GeneralFeatureButton
	GeneralFeatureBiometric
	GeneralFeatureDisplay
)

func (gf *GeneralFeatures) Decode(b []byte) error {
	if len(b) < 1 {
		return ErrInvalidLength
	}

	*gf = GeneralFeatures(b[0])

	return nil
}

type ApplicationIdentifier struct {
	RID          iso.RID
	Application  byte
	Version      iso.Version
	Serial       [4]byte
	Manufacturer Manufacturer
}

func (aid *ApplicationIdentifier) Decode(b []byte) error {
	if len(b) != 16 {
		return ErrInvalidLength
	}

	aid.RID = [5]byte(b[0:5])
	aid.Application = b[5]
	aid.Version = iso.Version{
		Major: int(b[6]),
		Minor: int(b[7]),
	}
	aid.Manufacturer = Manufacturer(binary.BigEndian.Uint16(b[8:10]))
	aid.Serial = [4]byte(b[10:14])

	return nil
}

type ExtendedLengthInfo struct {
	MaxCommandLength  uint16
	MaxResponseLength uint16
}

func (li *ExtendedLengthInfo) Decode(b []byte) error {
	if len(b) != 8 {
		return ErrInvalidLength
	}

	li.MaxCommandLength = binary.BigEndian.Uint16(b[2:4])
	li.MaxResponseLength = binary.BigEndian.Uint16(b[6:8])

	return nil
}

func decodeTime(b []byte) time.Time {
	tsc := binary.BigEndian.Uint32(b)
	return time.Unix(int64(tsc), 0)
}
