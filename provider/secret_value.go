package provider

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jmespath/go-jmespath"
)

// JMESPathNoMatchError is returned when the expression is valid but matches no value (nil result).
type JMESPathNoMatchError struct {
	Path        string
	ObjectAlias string
}

func (e *JMESPathNoMatchError) Error() string {
	return fmt.Sprintf("JMES Path - %s for object alias - %s does not point to a valid object.",
		e.Path, e.ObjectAlias)
}

// JMESPathInvalidSyntaxError is returned when jmespath.Search fails (invalid expression).
type JMESPathInvalidSyntaxError struct {
	Path string
}

func (e *JMESPathInvalidSyntaxError) Error() string {
	return fmt.Sprintf("Invalid JMES Path: %s.", e.Path)
}

// JMESPathInvalidJSONError is returned when the secret body is not JSON but jmesPath was configured.
type JMESPathInvalidJSONError struct {
	ObjectName string
}

func (e *JMESPathInvalidJSONError) Error() string {
	return fmt.Sprintf("Invalid JSON used with jmesPath in secret: %s.", e.ObjectName)
}

// JMESPathWrongResultTypeError is returned when JMESPath matches a non-string value.
type JMESPathWrongResultTypeError struct {
	Path string
}

func (e *JMESPathWrongResultTypeError) Error() string {
	return fmt.Sprintf("Invalid JMES search result type for path:%s. Only string is allowed.", e.Path)
}

// Returns true if the secrets content contribute to the error, so it might be client specific
func isJsonError(err error) bool {
	var nm *JMESPathNoMatchError
	var j *JMESPathInvalidJSONError
	var w *JMESPathWrongResultTypeError
	return errors.As(err, &nm) || errors.As(err, &j) || errors.As(err, &w)
}

// Returns true if the error caused by parameter configuration issue vs an issue that could be client specific
func isJsonFatalError(err error) bool {
	var a *JMESPathInvalidSyntaxError
	return errors.As(err, &a)
}

// Contains the actual contents of the secret fetched from either Secrete Manager
// or SSM Parameter Store along with the original descriptor.
type SecretValue struct {
	Value      []byte
	Descriptor SecretDescriptor
}

func (p *SecretValue) String() string { return "<REDACTED>" } // Do not log secrets
// parse out and return specified key value pairs from the secret
func (p *SecretValue) getJsonSecrets() (s []*SecretValue, e error) {

	jsonValues := make([]*SecretValue, 0)
	if len(p.Descriptor.JMESPath) == 0 {
		return jsonValues, nil
	}

	var data interface{}
	err := json.Unmarshal(p.Value, &data)
	if err != nil {
		return nil, &JMESPathInvalidJSONError{ObjectName: p.Descriptor.ObjectName}
	}

	//fetch all specified key value pairs`
	for _, jmesPathEntry := range p.Descriptor.JMESPath {

		jsonSecret, err := jmespath.Search(jmesPathEntry.Path, data)

		if err != nil {
			return nil, &JMESPathInvalidSyntaxError{Path: jmesPathEntry.Path}
		}

		if jsonSecret == nil {
			return nil, &JMESPathNoMatchError{
				Path:        jmesPathEntry.Path,
				ObjectAlias: jmesPathEntry.ObjectAlias,
			}
		}

		jsonSecretAsString, isString := jsonSecret.(string)

		if !isString {
			return nil, &JMESPathWrongResultTypeError{Path: jmesPathEntry.Path}
		}

		descriptor := p.Descriptor.getJmesEntrySecretDescriptor(&jmesPathEntry)

		secretValue := SecretValue{
			Value:      []byte(jsonSecretAsString),
			Descriptor: descriptor,
		}
		jsonValues = append(jsonValues, &secretValue)

	}
	return jsonValues, nil
}
