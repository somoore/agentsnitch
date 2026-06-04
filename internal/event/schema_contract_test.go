package event

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestEventSchemaMatchesGoWireStructs(t *testing.T) {
	schema := loadEventSchema(t)
	defs := schemaDefs(t, schema)

	assertSchemaPropertiesMatchStruct(t, defs, "AgentInfo", AgentInfo{})
	assertSchemaPropertiesMatchStruct(t, defs, "SessionInfo", SessionInfo{})
	assertSchemaPropertiesMatchStruct(t, defs, "SemanticEvent", SemanticEvent{})
	assertSchemaPropertiesMatchStruct(t, defs, "NetworkFlowEvent", NetworkFlowEvent{})
	assertSchemaPropertiesMatchStruct(t, defs, "CorrelatedEvent", CorrelatedEvent{})
	assertSchemaPropertiesMatchStruct(t, defs, "ProcessNode", ProcessNode{})
	assertSchemaPropertiesMatchStruct(t, defs, "AgentLifecycleEvent", AgentLifecycleEvent{})
}

func TestNetworkSchemaCoversSwiftFlowEvent(t *testing.T) {
	schema := loadEventSchema(t)
	networkProps := schemaProperties(t, schemaDefs(t, schema), "NetworkFlowEvent")

	swiftPath := filepath.Join(repoRoot(t), "extension", "AgentSnitchNetworkExtension.swift")
	body, err := os.ReadFile(swiftPath)
	if err != nil {
		t.Fatalf("read Swift extension: %v", err)
	}
	fields := swiftFlowEventFields(t, string(body))
	for field := range fields {
		if _, ok := networkProps[field]; !ok {
			t.Fatalf("Swift FlowEvent field %q is missing from NetworkFlowEvent schema", field)
		}
	}
}

func loadEventSchema(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "schemas", "agentsnitch.event.schema.json"))
	if err != nil {
		t.Fatalf("read event schema: %v", err)
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatalf("parse event schema: %v", err)
	}
	return schema
}

func schemaDefs(t *testing.T, schema map[string]interface{}) map[string]interface{} {
	t.Helper()
	defs, ok := schema["$defs"].(map[string]interface{})
	if !ok {
		t.Fatalf("schema missing $defs")
	}
	return defs
}

func schemaProperties(t *testing.T, defs map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	definition, ok := defs[name].(map[string]interface{})
	if !ok {
		t.Fatalf("schema missing definition %s", name)
	}
	props, ok := definition["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("schema definition %s missing properties", name)
	}
	return props
}

func assertSchemaPropertiesMatchStruct(t *testing.T, defs map[string]interface{}, name string, value interface{}) {
	t.Helper()
	props := schemaProperties(t, defs, name)
	fields := jsonFieldNames(reflect.TypeOf(value))
	if !reflect.DeepEqual(fields, mapKeys(props)) {
		t.Fatalf("%s schema properties differ from Go struct\nschema: %v\nstruct: %v", name, mapKeys(props), fields)
	}
}

func jsonFieldNames(typ reflect.Type) []string {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		names = append(names, name)
	}
	return sortedStrings(names)
}

func swiftFlowEventFields(t *testing.T, body string) map[string]struct{} {
	t.Helper()
	start := strings.Index(body, "struct FlowEvent: Codable {")
	if start < 0 {
		t.Fatalf("Swift FlowEvent struct not found")
	}
	end := strings.Index(body[start:], "struct SigningInfo: Codable {")
	if end < 0 {
		t.Fatalf("Swift FlowEvent SigningInfo boundary not found")
	}
	block := body[start : start+end]
	re := regexp.MustCompile("let\\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\\s*:")
	matches := re.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("Swift FlowEvent fields not found")
	}
	fields := map[string]struct{}{}
	for _, match := range matches {
		fields[match[1]] = struct{}{}
	}
	return fields
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func mapKeys(values map[string]interface{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return sortedStrings(keys)
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
