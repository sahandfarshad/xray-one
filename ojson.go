package main

// Order-preserving JSON. Xray's config is edited by hand and by other tools
// (Muse99), so XRay One keeps key order and every unknown field intact.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

type OMap struct {
	keys []string
	vals map[string]any
}

func NewOMap() *OMap { return &OMap{vals: map[string]any{}} }

// om builds an ordered object from key/value pairs.
func om(kv ...any) *OMap {
	m := NewOMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}

func (m *OMap) Get(k string) any {
	if m == nil {
		return nil
	}
	return m.vals[k]
}

func (m *OMap) Has(k string) bool {
	if m == nil {
		return false
	}
	_, ok := m.vals[k]
	return ok
}

func (m *OMap) Set(k string, v any) {
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
}

func (m *OMap) Delete(k string) {
	if _, ok := m.vals[k]; !ok {
		return
	}
	delete(m.vals, k)
	for i, kk := range m.keys {
		if kk == k {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			break
		}
	}
}

func (m *OMap) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	writeJSON(&b, m, "")
	return b.Bytes(), nil
}

func ParseOrdered(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := NewOMap()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				m.Set(k, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", v)
	default:
		return v, nil
	}
}

func EncodeIndent(v any) []byte {
	var b bytes.Buffer
	writeJSON(&b, v, "")
	b.WriteByte('\n')
	return b.Bytes()
}

func writeString(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

func writeJSON(b *bytes.Buffer, v any, ind string) {
	switch t := v.(type) {
	case *OMap:
		if t == nil || len(t.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range t.keys {
			b.WriteString(ind + "  ")
			writeString(b, k)
			b.WriteString(": ")
			writeJSON(b, t.vals[k], ind+"  ")
			if i < len(t.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(ind + "}")
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range t {
			b.WriteString(ind + "  ")
			writeJSON(b, e, ind+"  ")
			if i < len(t)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(ind + "]")
	case []string:
		arr := make([]any, len(t))
		for i, s := range t {
			arr[i] = s
		}
		writeJSON(b, arr, ind)
	case string:
		writeString(b, t)
	case json.Number:
		b.WriteString(string(t))
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		b.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
	default:
		raw, _ := json.Marshal(t)
		b.Write(raw)
	}
}

// ---- small accessors ----

func asMap(v any) *OMap {
	m, _ := v.(*OMap)
	return m
}

func asArr(v any) []any {
	a, _ := v.([]any)
	return a
}

func asStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return string(t)
	case int:
		return strconv.Itoa(t)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func path(m *OMap, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm := asMap(cur)
		if mm == nil {
			return nil
		}
		cur = mm.Get(k)
	}
	return cur
}

func pathStr(m *OMap, keys ...string) string { return asStr(path(m, keys...)) }
