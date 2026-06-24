package schema

// FieldType defines the UI input type for a config field.
type FieldType string

const (
	FieldText     FieldType = "text"
	FieldPassword FieldType = "password"
	FieldNumber   FieldType = "number"
	FieldBool     FieldType = "bool"
	FieldSelect   FieldType = "select"
	FieldArray    FieldType = "array" // slice of sub-fields (e.g. tunnels[])
)

// Field describes a single form input mapped to a YAML key.
// Key supports dot-notation for nested fields: "server.port"
type Field struct {
	Key        string    `yaml:"key"`
	Label      string    `yaml:"label"`
	Type       FieldType `yaml:"type"`
	Options    []string  `yaml:"options,omitempty"`    // for FieldSelect
	Default    any       `yaml:"default"`
	ItemFields []Field   `yaml:"item_fields,omitempty"` // for FieldArray
}

// Section groups related fields under a titled header in the UI.
type Section struct {
	Title  string  `yaml:"title"`
	Fields []Field `yaml:"fields"`
}

// ConfigSchema is the full schema definition for one YAML config file.
type ConfigSchema struct {
	Name     string    `yaml:"name"`
	File     string    `yaml:"file"` // e.g. "client.yaml"
	Sections []Section `yaml:"sections"`
}
