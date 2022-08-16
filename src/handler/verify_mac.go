package handler

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"

	"fmt"
)

func (r *RequestHandler) VerifyMac() Response {
	var body *kms.VerifyMacInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.VerifyMacInput{}
	}

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if body.MacAlgorithm == nil {
		msg := "MacAlgorithm is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.Message) == 0 {
		msg := "1 validation error detected: Value at 'Message' failed to satisfy constraint: Member must have " +
			"length greater than or equal to 1"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Message) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Message' failed to satisfy "+
			"constraint: Member must have minimum length of 1 and maximum length of 4096.", string(body.Message))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Mac) == 0 {
		msg := "1 validation error detected: Value at 'Mac' failed to satisfy constraint: Member must have " +
			"length greater than or equal to 1"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	key, response := r.getUsableKey(*body.KeyId)

	if !response.Empty() {
		return response
	}

	var verifyResult bool

	switch k := key.(type) {
	case *cmk.MacKey:
		verifyResult, err = k.VerifyMac(body.Message, body.Mac, *body.MacAlgorithm)
		if err != nil {
			msg := fmt.Sprintf("Unable to generate MAC: %s", err)
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException("")
		}
	default:
		return NewValidationExceptionResponse("key type not supported for mac")
	}

	return NewResponse(200, &struct {
		KeyId        string
		MacAlgorithm string
		MacValid     bool
	}{
		KeyId:        *body.KeyId,
		MacAlgorithm: *body.MacAlgorithm,
		MacValid:     verifyResult,
	})
}
