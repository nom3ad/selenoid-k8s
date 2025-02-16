package service

import (
	"encoding/json"
	"net"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/aerokube/selenoid/session"
)

func parseCommaSeparatedString(value string) []string {
	var list []string
	for _, it := range strings.Split(value, ",") {
		value := strings.TrimSpace(it)
		if value != "" {
			list = append(list, value)
		}
	}
	return list
}

func jsonUnmarshalIfNonEmpty(s string, v any) error {
	s = strings.TrimSpace(s)
	if s != "" {
		return json.Unmarshal([]byte(s), v)
	}
	return nil
}

func jsonMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fullyQualifiedImageName(image string) string {
	dockerRegistryDomain := "docker.io"
	dockerOfficialNamespace := "library"
	parts := strings.Split(strings.Trim(image, "/"), "/")
	if len(parts) == 1 {
		image = dockerRegistryDomain + "/" + dockerOfficialNamespace + "/" + parts[0]
	}
	if len(parts) == 2 && !strings.Contains(parts[0], ".") {
		image = dockerRegistryDomain + "/" + parts[0] + "/" + parts[1]
	}
	return image
}

// func ptrTo[T any](v T) *T {
// 	return &v
// }

func int64Ptr[T int | int32 | int8 | int16 | int64 | float32 | float64](v T) *int64 {
	i := int64(v)
	return &i
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		v := strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func nonEmptyStringPtr(value string) *string {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	return &v
}

func mustParseInt(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		panic(err)
	}
	return n
}
func parseKVString(value string) map[string]string {
	mapping := map[string]string{}
	for _, it := range strings.Split(value, ",") {
		if it == "" {
			continue
		}
		kv := strings.SplitN(it, "=", 2)
		key := kv[0]
		if key == "" {
			continue
		}
		value := ""
		if len(kv) == 2 {
			value = kv[1]
		}
		mapping[key] = value
	}
	return mapping
}

var Ports = struct { // common struct
	Selenium, VNC, Devtools, Fileserver, Clipboard int32
}{
	Selenium:   4444,
	VNC:        5900,
	Devtools:   7070,
	Fileserver: 8080,
	Clipboard:  9090,
}

func buildHostPort(ip string, caps session.Caps) session.HostPort {
	fn := func(ip string, servicePort int32) string {
		port := strconv.Itoa(int(servicePort))
		return net.JoinHostPort(ip, port)
	}
	hp := session.HostPort{
		Selenium:   fn(ip, Ports.Selenium),
		Fileserver: fn(ip, Ports.Fileserver),
		Clipboard:  fn(ip, Ports.Clipboard),
		Devtools:   fn(ip, Ports.Devtools),
	}

	if caps.VNC {
		hp.VNC = fn(ip, Ports.VNC)
	}

	return hp
}

// https://stackoverflow.com/questions/42664837/how-to-access-unexported-struct-fields

func GetUnexportedField(field reflect.Value) any {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

func SetUnexportedField(field reflect.Value, value any) {
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).
		Elem().
		Set(reflect.ValueOf(value))
}

func SetUnexportedFieldOfStruct(structPtr any, fieldName string, value any) {
	field := reflect.ValueOf(structPtr).Elem().FieldByName(fieldName)
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).
		Elem().
		Set(reflect.ValueOf(value))
}

func Range(min, max, step int) []int {
	slice := make([]int, 0, (max-min)/step+1)
	for i := min; i <= max; i += step {
		slice = append(slice, i)
	}
	return slice
}

func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func Contains[T comparable](slice []T, v T) bool {
	for _, s := range slice {
		if v == s {
			return true
		}
	}
	return false
}
