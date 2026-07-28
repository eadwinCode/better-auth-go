package betterauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
)

// ValidationKind is the JSON/query value type required by a FieldValidation.
type ValidationKind string

const (
	ValidationString  ValidationKind = "string"
	ValidationNumber  ValidationKind = "number"
	ValidationInteger ValidationKind = "integer"
	ValidationBoolean ValidationKind = "boolean"
	ValidationObject  ValidationKind = "object"
	ValidationArray   ValidationKind = "array"
)

// FieldValidation declares a strict, dependency-free input rule.
type FieldValidation struct {
	Kind      ValidationKind
	Required  bool
	Nullable  bool
	MinLength int
	MaxLength int
	Enum      []string
}

// ObjectValidator validates JSON objects and URL query values. Unknown fields
// are rejected unless AllowUnknown is explicitly enabled.
type ObjectValidator struct {
	Fields       map[string]FieldValidation
	AllowUnknown bool
}

func cloneEndpointValidator(validator EndpointValidator) EndpointValidator {
	switch typed := validator.(type) {
	case ObjectValidator:
		return cloneObjectValidator(typed)
	case *ObjectValidator:
		if typed == nil {
			return nil
		}
		cloned := cloneObjectValidator(*typed)
		return &cloned
	default:
		return validator
	}
}

func cloneObjectValidator(validator ObjectValidator) ObjectValidator {
	fields := make(map[string]FieldValidation, len(validator.Fields))
	for name, rule := range validator.Fields {
		rule.Enum = slices.Clone(rule.Enum)
		fields[name] = rule
	}
	validator.Fields = fields
	return validator
}

// ValidateConfiguration enables fail-closed validation during server
// construction.
func (validator ObjectValidator) ValidateConfiguration() error {
	for name, rule := range validator.Fields {
		if name == "" {
			return errors.New("validator field name is empty")
		}
		switch rule.Kind {
		case ValidationString, ValidationNumber, ValidationInteger, ValidationBoolean,
			ValidationObject, ValidationArray:
		default:
			return fmt.Errorf("field %q has an invalid validator kind", name)
		}
		if rule.MinLength < 0 || rule.MaxLength < 0 ||
			(rule.MaxLength > 0 && rule.MaxLength < rule.MinLength) {
			return fmt.Errorf("field %q has invalid length bounds", name)
		}
		if len(rule.Enum) > 0 && rule.Kind != ValidationString {
			return fmt.Errorf("field %q has an enum on a non-string rule", name)
		}
	}
	return nil
}

func (validator ObjectValidator) Validate(value any) error {
	object, err := validationObject(value)
	if err != nil {
		return err
	}
	for name, rule := range validator.Fields {
		field, exists := object[name]
		if !exists {
			if rule.Required {
				return fmt.Errorf("field %q is required", name)
			}
			continue
		}
		if field == nil && rule.Nullable {
			continue
		}
		if err := validateField(name, field, rule); err != nil {
			return err
		}
	}
	if !validator.AllowUnknown {
		for name := range object {
			if _, exists := validator.Fields[name]; !exists {
				return fmt.Errorf("field %q is not allowed", name)
			}
		}
	}
	return nil
}

func validationObject(value any) (map[string]any, error) {
	switch input := value.(type) {
	case map[string]any:
		return input, nil
	case url.Values:
		result := make(map[string]any, len(input))
		for key, values := range input {
			switch len(values) {
			case 0:
				result[key] = ""
			case 1:
				result[key] = values[0]
			default:
				result[key] = slices.Clone(values)
			}
		}
		return result, nil
	case nil:
		return map[string]any{}, nil
	default:
		return nil, errors.New("input must be an object")
	}
}

func validateField(name string, value any, rule FieldValidation) error {
	if rule.MinLength < 0 || rule.MaxLength < 0 ||
		(rule.MaxLength > 0 && rule.MaxLength < rule.MinLength) {
		return fmt.Errorf("field %q has an invalid validator", name)
	}
	switch rule.Kind {
	case ValidationString:
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("field %q must be a string", name)
		}
		if len(text) < rule.MinLength || rule.MaxLength > 0 && len(text) > rule.MaxLength {
			return fmt.Errorf("field %q has an invalid length", name)
		}
		if len(rule.Enum) > 0 && !slices.Contains(rule.Enum, text) {
			return fmt.Errorf("field %q is not an allowed value", name)
		}
	case ValidationNumber, ValidationInteger:
		number, ok := finiteNumber(value)
		if !ok || rule.Kind == ValidationInteger && math.Trunc(number) != number {
			return fmt.Errorf("field %q must be a %s", name, rule.Kind)
		}
	case ValidationBoolean:
		if _, ok := value.(bool); !ok {
			// Query parameters are strings; accept only canonical booleans.
			text, stringValue := value.(string)
			if !stringValue || (text != strconv.FormatBool(true) && text != strconv.FormatBool(false)) {
				return fmt.Errorf("field %q must be a boolean", name)
			}
		}
	case ValidationObject:
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("field %q must be an object", name)
		}
	case ValidationArray:
		switch values := value.(type) {
		case []any:
			if len(values) < rule.MinLength || rule.MaxLength > 0 && len(values) > rule.MaxLength {
				return fmt.Errorf("field %q has an invalid length", name)
			}
		case []string:
			if len(values) < rule.MinLength || rule.MaxLength > 0 && len(values) > rule.MaxLength {
				return fmt.Errorf("field %q has an invalid length", name)
			}
		default:
			return fmt.Errorf("field %q must be an array", name)
		}
	default:
		return fmt.Errorf("field %q has an invalid validator kind", name)
	}
	return nil
}

func finiteNumber(value any) (float64, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil && !math.IsInf(parsed, 0) && !math.IsNaN(parsed)
	case float64:
		return number, !math.IsInf(number, 0) && !math.IsNaN(number)
	case string:
		parsed, err := strconv.ParseFloat(number, 64)
		return parsed, err == nil && !math.IsInf(parsed, 0) && !math.IsNaN(parsed)
	default:
		return 0, false
	}
}

func validatePluginEndpointInput(endpoint PluginEndpoint, context *HookContext) (err error) {
	if endpoint.BodyValidator != nil {
		if context.bodyDecodeError != nil {
			return publicError(CodeBadRequest, "Invalid endpoint input.", http.StatusBadRequest, context.bodyDecodeError)
		}
		if err := safelyValidateEndpoint(endpoint.BodyValidator, context.Body); err != nil {
			return publicError(CodeBadRequest, "Invalid endpoint input.", http.StatusBadRequest, err)
		}
	}
	if endpoint.QueryValidator != nil {
		if err := safelyValidateEndpoint(endpoint.QueryValidator, context.Query); err != nil {
			return publicError(CodeBadRequest, "Invalid endpoint input.", http.StatusBadRequest, err)
		}
	}
	return nil
}

func safelyValidateEndpoint(validator EndpointValidator, value any) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("betterauth: endpoint validator panic: %v", recovered)
		}
	}()
	return validator.Validate(value)
}
