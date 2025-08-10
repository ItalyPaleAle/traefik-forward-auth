//nolint:forbidigo,errcheck
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const (
	docsFileDest = "docs/03-all-configuration-options.md"
)

func generateFromStruct(dir string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filepath.Join(dir, "config.go"), nil, parser.ParseComments)
	if err != nil {
		return err
	}

	outYAML, err := os.Create("config.sample.yaml")
	if err != nil {
		return err
	}
	defer outYAML.Close()

	outFileMD, err := os.Create("config.md")
	if err != nil {
		return err
	}
	defer outFileMD.Close()

	outBufMD := &bytes.Buffer{}
	outMD := io.MultiWriter(outBufMD, outFileMD)

	fmt.Fprint(outMD, "| Name | Type | Description | |\n")
	fmt.Fprint(outMD, "| --- | --- | --- | --- |\n")

	// Map to store struct types defined in the file
	structTypes := make(map[string]*ast.StructType)

	// First pass: collect all struct types
	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		structTypes[typeSpec.Name.Name] = structType
		return true
	})

	// Process the Config struct
	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Config" {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		processStruct(structType, "", "", outYAML, outMD, structTypes)
		return false
	})

	// Parse providers and generate examples dynamically
	err = generatePortalExamples(outYAML, filepath.Join(dir, "providers-config.go"))
	if err != nil {
		return fmt.Errorf("failed to generate portal examples: %w", err)
	}

	// Replace the configuration table in the docs file file
	readme, err := os.ReadFile(filepath.Join(".", docsFileDest))
	if err != nil {
		return err
	}

	const (
		beginMarker = "<!-- BEGIN CONFIG TABLE -->"
		endMarker   = "<!-- END CONFIG TABLE -->"
	)
	begin := bytes.Index(readme, []byte(beginMarker)) + len(beginMarker)
	end := bytes.Index(readme, []byte(endMarker))

	readmeFile, err := os.Create(filepath.Join(".", docsFileDest))
	if err != nil {
		return err
	}
	defer readmeFile.Close()
	readmeFile.Write(readme[:begin])
	readmeFile.Write([]byte{'\n'})
	io.Copy(readmeFile, outBufMD)
	readmeFile.Write([]byte{'\n'})
	readmeFile.Write(readme[end:])

	return nil
}

// processStruct processes a struct type recursively, generating documentation for each field
func processStruct(structType *ast.StructType, prefix string, parentYamlPath string, outYAML io.Writer, outMD io.Writer, structTypes map[string]*ast.StructType) {
	for _, field := range structType.Fields.List {
		// Skip fields without tags
		if field.Tag == nil {
			continue
		}

		unquoted, _ := strconv.Unquote(field.Tag.Value)
		tags := reflect.StructTag(unquoted)
		yamlTag, ok := tags.Lookup("yaml")
		if !ok || yamlTag == "" || yamlTag == "-" {
			continue
		}

		// Skip deprecated fields
		deprecatedTag, _ := tags.Lookup("deprecated")
		deprecated, _ := strconv.ParseBool(deprecatedTag)
		if deprecated {
			continue
		}

		// Build the full YAML path
		fullYamlPath := yamlTag
		if parentYamlPath != "" {
			fullYamlPath = parentYamlPath + "." + yamlTag
		}

		// Check if this field is a struct
		isStructField := false
		var structName string
		ident, ok := field.Type.(*ast.Ident)
		if ok {
			structName = ident.Name
			_, isStructField = structTypes[structName]
		}

		if !isStructField {
			// Handle regular field
			processField(field, fullYamlPath, outYAML, outMD, prefix)
			continue
		}

		// Process nested struct
		nestedStruct := structTypes[structName]
		if nestedStruct != nil {
			// Only output a header for this struct if it's not the root
			if parentYamlPath != "" {
				fmt.Fprintf(outYAML, "## %s\n", fullYamlPath)
				if field.Doc != nil && field.Doc.Text() != "" {
					fmt.Fprintf(outYAML, "## Description:\n")
					for _, line := range strings.Split(field.Doc.Text(), "\n") {
						if line != "" {
							fmt.Fprintf(outYAML, "##   %s\n", line)
						}
					}
				}
				// Generate proper YAML indentation for nested structures
				fmt.Fprintf(outYAML, "%s:\n", yamlTag)
			} else {
				// For top-level fields
				fmt.Fprintf(outYAML, "%s:\n", yamlTag)
			}

			// Process nested fields with appropriate indentation
			processStruct(nestedStruct, prefix+"  ", fullYamlPath, outYAML, outMD, structTypes)
		}
	}
}

// processField handles a single field, generating documentation
func processField(field *ast.Field, yamlTag string, outYAML io.Writer, outMD io.Writer, prefix string) {
	var (
		defaultText, doc                 string
		required, recommended, lastEmpty bool
	)

	// Get the last part of the YAML path for field name (after the last dot)
	fieldName := yamlTag
	if idx := strings.LastIndex(yamlTag, "."); idx > -1 {
		fieldName = yamlTag[idx+1:]
	}

	// Field type
	typ := fieldTypeName(field)

	// Parse field documentation
	fmt.Fprintf(outYAML, "%s## %s (%s)\n", prefix, yamlTag, typ)
	fmt.Fprintf(outMD, "| <a id=\"config-opt-%s\"></a>`%s` | %s | ", strings.ToLower(strings.ReplaceAll(yamlTag, ".", "-")), yamlTag, typ)
	if field.Doc != nil {
		doc = field.Doc.Text()
	}
	var mdFooter string
	if doc != "" {
		fmt.Fprintf(outYAML, "%s## Description:\n", prefix)
		for i, line := range strings.Split(doc, "\n") {
			if line == "" {
				lastEmpty = true
				continue
			}

			switch {
			case strings.HasPrefix(line, "+default "):
				defaultText = strings.TrimPrefix(line, "+default ")
			case strings.TrimSpace(line) == "+required":
				required = true
			case strings.TrimSpace(line) == "+recommended":
				recommended = true
			default:
				if lastEmpty {
					fmt.Fprintf(outYAML, "%s##\n", prefix)
					fmt.Fprint(outMD, "<br>")
				}
				fmt.Fprintf(outYAML, "%s##   %s\n", prefix, line)
				if i > 0 {
					fmt.Fprint(outMD, "<br>"+line)
				} else {
					fmt.Fprint(outMD, line)
				}
				lastEmpty = false
			}
		}

		if defaultText != "" {
			fmt.Fprintf(outYAML, "%s## Default: %s\n", prefix, defaultText)
			mdFooter = "Default: _" + defaultText + "_"
		}
	}

	if required {
		fmt.Fprintf(outYAML, "%s## Required\n%s%s:\n\n", prefix, prefix, fieldName)
		// We can't have a default value if it's required
		mdFooter = "**Required**"
	} else {
		if recommended {
			if mdFooter != "" {
				mdFooter = "Recommended<br>" + mdFooter
			} else {
				mdFooter = "Recommended"
			}
		}
		fmt.Fprintf(outYAML, "%s#%s: \n\n", prefix, fieldName)
	}
	fmt.Fprintf(outMD, "| %s |\n", mdFooter)
}

// generatePortalExamples adds example configurations for portals and all supported providers dynamically
func generatePortalExamples(outYAML io.Writer, providerFilePath string) error {
	// First output the empty portals array as the default value
	fmt.Fprintf(outYAML, "portals: []\n\n")

	// Commented examples header
	fmt.Fprintf(outYAML, "###\n### Example Portal Configurations\n###\n")
	fmt.Fprintf(outYAML, "## The following are examples of portal configurations with different providers\n\n")

	// Parse the providers file to extract provider config struct definitions
	fsetProviders := token.NewFileSet()
	providersNode, err := parser.ParseFile(fsetProviders, providerFilePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	// Parse config file to find portal / provider wrapper structs
	configFilePath := filepath.Join(filepath.Dir(providerFilePath), "config.go")
	fsetConfig := token.NewFileSet()
	configNode, _ := parser.ParseFile(fsetConfig, configFilePath, nil, parser.ParseComments)

	var portalStruct *ast.StructType
	var providerEntryStruct *ast.StructType
	if configNode != nil {
		ast.Inspect(configNode, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			stDecl, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			switch ts.Name.Name {
			case "ConfigPortal":
				portalStruct = stDecl
			case "ConfigPortalProvider":
				providerEntryStruct = stDecl
			}
			return true
		})
	}

	// Map to collect provider config structs and their fields
	providerTypes := make(map[string]*struct {
		structType   *ast.StructType
		displayName  string
		providerType string
		doc          string
	})
	providerNames := make([]string, 0)

	// Collect provider config structs
	ast.Inspect(providersNode, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		typeName := typeSpec.Name.Name
		if strings.HasPrefix(typeName, "ProviderConfig_") {
			providerType := strings.TrimPrefix(typeName, "ProviderConfig_")
			doc := ""
			if typeSpec.Doc != nil {
				doc = typeSpec.Doc.Text()
			}
			providerNames = append(providerNames, typeName)
			providerTypes[typeName] = &struct {
				structType   *ast.StructType
				displayName  string
				providerType string
				doc          string
			}{
				structType:   structType,
				displayName:  getProviderDisplayName(providerType),
				providerType: getProviderType(providerType),
				doc:          doc,
			}
		}
		return true
	})

	// Generate commented example for each provider type
	slices.Sort(providerNames)
	for _, k := range providerNames {
		p := providerTypes[k]
		generateProviderExample(outYAML, portalStruct, providerEntryStruct, p.structType, p.providerType, p.displayName)
	}

	return nil
}

// exampleValueForType returns a simple example for a type (string placeholders)
func exampleValueForType(expr ast.Expr) string {
	ft := types.ExprString(expr)
	switch ft {
	case "string":
		return `""`
	case "int":
		return "0"
	case "bool":
		return "false"
	case "time.Duration":
		return "0s"
	case "[]string":
		return "[]"
	default:
		return "" // unknown or nested
	}
}

// generateProviderExample creates a commented YAML example for a single provider (dynamic fields)
func generateProviderExample(outYAML io.Writer, portalStruct, providerEntryStruct, providerConfigStruct *ast.StructType, providerType string, displayName string) {
	portalName := providerType + "-portal"
	displayTitle := displayName + " Authentication"

	w := func(format string, a ...any) { fmt.Fprintf(outYAML, "# "+format, a...) }

	w("Example portal using %s authentication\n", displayName)
	// Start portal block root sign '-' line specifically; find portal name field first
	w("- ")
	// Emit portal fields dynamically; we buffer to collect then rewrite with proper indentation

	// We'll manually output portal fields to preserve ordering from struct
	if portalStruct != nil {
		for i, field := range portalStruct.Fields.List {
			if field.Tag == nil {
				continue
			}
			unquoted, _ := strconv.Unquote(field.Tag.Value)
			tags := reflect.StructTag(unquoted)
			yamlTag, ok := tags.Lookup("yaml")
			if !ok || yamlTag == "" || yamlTag == "-" {
				continue
			}
			yamlTag = strings.Split(yamlTag, ",")[0]
			deprecatedTag, _ := tags.Lookup("deprecated")
			if dep, _ := strconv.ParseBool(deprecatedTag); dep {
				continue
			}

			// First field we already started with '- ' prefix; subsequent fields indented two spaces
			indent := strings.Repeat(" ", 2)
			prefix := strings.Repeat(" ", 2)
			if i == 0 {
				indent = ""
				prefix = ""
			}
			value := ""
			switch yamlTag {
			case "name":
				value = portalName
			case "displayName":
				value = fmt.Sprintf(`"%s"`, displayTitle)
			case "providers":
				// providers list header
				fmt.Println("HERE", prefix, "PROVIDERS")
				w("%sproviders:\n", prefix)
				// generate single provider entry dynamically
				generateProviderEntryExample(w, providerEntryStruct, providerConfigStruct, providerType)
				continue
			default:
				// Extract default value from field documentation
				if field.Doc != nil {
					doc := field.Doc.Text()
					for _, line := range strings.Split(doc, "\n") {
						if strings.HasPrefix(line, "+default ") {
							value = strings.TrimPrefix(line, "+default ")
							break
						}
					}
				}
				if value == "" {
					value = exampleValueForType(field.Type)
				}
			}
			if i == 0 {
				w("%s: %s\n", yamlTag, value)
			} else {
				w("%s%s: %s\n", indent, yamlTag, value)
			}
		}
	}
	w("\n")
}

// generateProviderEntryExample emits a single provider entry with dynamic fields
func generateProviderEntryExample(w func(string, ...any), providerEntryStruct, providerConfigStruct *ast.StructType, providerType string) {
	w("  - ")
	if providerEntryStruct != nil {
		for i, field := range providerEntryStruct.Fields.List {
			if field.Tag == nil {
				continue
			}
			unquoted, _ := strconv.Unquote(field.Tag.Value)
			tags := reflect.StructTag(unquoted)
			yamlTag, ok := tags.Lookup("yaml")
			if !ok || yamlTag == "" || yamlTag == "-" {
				continue
			}
			yamlTag = strings.Split(yamlTag, ",")[0]
			deprecatedTag, _ := tags.Lookup("deprecated")
			if dep, _ := strconv.ParseBool(deprecatedTag); dep {
				continue
			}

			indent := strings.Repeat(" ", 4)
			if i == 0 {
				indent = ""
			}
			value := ""
			switch yamlTag {
			case "provider":
				value = providerType
			case "name", "displayName", "icon", "color":
				value = `""`
			case "config":
				w("%sconfig:\n", indent)
				generateProviderSpecificConfig(w, providerConfigStruct, providerType)
				continue
			default:
				value = exampleValueForType(field.Type)
			}
			if i == 0 {
				w("%s: %s\n", yamlTag, value)
			} else {
				w("%s%s: %s\n", indent, yamlTag, value)
			}
		}
	} else {
		// Fallback minimal provider entry
		w("provider: %s\n", providerType)
		w("    config:\n")
		generateProviderSpecificConfig(w, providerConfigStruct, providerType)
	}
}

// generateProviderSpecificConfig emits the provider-specific config struct commented documentation and example values
func generateProviderSpecificConfig(w func(string, ...any), providerConfigStruct *ast.StructType, providerType string) {
	if providerConfigStruct == nil {
		return
	}
	fieldIndent := "        "
	for _, field := range providerConfigStruct.Fields.List {
		if field.Tag == nil {
			continue
		}
		unquoted, _ := strconv.Unquote(field.Tag.Value)
		tags := reflect.StructTag(unquoted)
		yamlTag, ok := tags.Lookup("yaml")
		if !ok || yamlTag == "" || yamlTag == "-" {
			continue
		}
		yamlTag = strings.Split(yamlTag, ",")[0]
		deprecatedTag, _ := tags.Lookup("deprecated")
		if dep, _ := strconv.ParseBool(deprecatedTag); dep {
			continue
		}

		var (
			defaultText string
			required    bool
			lastEmpty   bool
			doc         string
		)
		if field.Doc != nil {
			doc = field.Doc.Text()
		}
		typ := fieldTypeName(field)
		w("%s## %s (%s)\n", fieldIndent, yamlTag, typ)
		if doc != "" {
			w("%s## Description:\n", fieldIndent)
			for _, line := range strings.Split(doc, "\n") {
				if line == "" {
					lastEmpty = true
					continue
				}
				switch {
				case strings.HasPrefix(line, "+default "):
					defaultText = strings.TrimPrefix(line, "+default ")
				case strings.TrimSpace(line) == "+required":
					required = true
				case strings.TrimSpace(line) == "+recommended":
					// ignore
				default:
					if lastEmpty {
						w("%s##\n", fieldIndent)
					}
					w("%s##   %s\n", fieldIndent, line)
					lastEmpty = false
				}
			}
			if defaultText != "" {
				w("%s## Default: %s\n", fieldIndent, defaultText)
			}
			if required {
				w("%s## Required\n", fieldIndent)
			}
		}
		exampleValue := generateExampleValue(field.Type, yamlTag, providerType, fieldIndent)
		if exampleValue != "" {
			if strings.HasPrefix(exampleValue, "\n") {
				w("%s%s:\n", fieldIndent, yamlTag)
				lines := strings.Split(exampleValue[1:], "\n")
				for _, l := range lines {
					if l == "" {
						continue
					}
					w("%s%s\n", fieldIndent, l)
				}
			} else {
				w("%s%s: %s\n", fieldIndent, yamlTag, exampleValue)
			}
		}
		w("\n")
	}
}

// getProviderType converts the struct name to the actual provider type used in configuration
func getProviderType(name string) string {
	switch name {
	case "GitHub":
		return "github"
	case "Google":
		return "google"
	case "MicrosoftEntraID":
		return "microsoftentraid"
	case "OpenIDConnect":
		return "openidconnect"
	case "TailscaleWhois":
		return "tailscalewhois"
	default:
		return strings.ToLower(name)
	}
}

// getProviderDisplayName converts the struct name to the display name
func getProviderDisplayName(name string) string {
	switch name {
	case "GitHub":
		return "GitHub"
	case "Google":
		return "Google"
	case "MicrosoftEntraID":
		return "Microsoft Entra ID"
	case "OpenIDConnect":
		return "OpenID Connect"
	case "TailscaleWhois":
		return "Tailscale Whois"
	default:
		return name
	}
}

// generateExampleValue creates an appropriate example value based on field type
func generateExampleValue(fieldType ast.Expr, fieldName string, providerType string, fieldPrefix string) string {
	ft := types.ExprString(fieldType)

	// Provider/name specific
	switch {
	case fieldName == "clientID":
		switch providerType {
		case "google":
			return `"your-google-client-id.apps.googleusercontent.com"`
		default:
			return `"your-client-id"`
		}
	case fieldName == "clientSecret":
		return `"your-client-secret"`
	case fieldName == "tenantID" && providerType == "microsoftentraid":
		return `"your-tenant-id"`
	case fieldName == "tokenIssuer" && providerType == "openidconnect":
		return `"https://your-identity-provider/.well-known/openid-configuration"`
	case fieldName == "allowedTailnet" && providerType == "tailscalewhois":
		return `"yourtailnet.ts.net"`
	case fieldName == "azureFederatedIdentity" && providerType == "microsoftentraid":
		return `"ManagedIdentity"`
	}

	switch ft {
	case "string":
		return `""`
	case "int":
		return "0"
	case "bool":
		return "false"
	case "time.Duration":
		return "0s"
	case "[]string":
		return "\n" + fieldPrefix + "  - \"example1\"\n" + fieldPrefix + "  - \"example2\""
	default:
		return ""
	}
}

// fieldTypeName returns a human-readable name for a field type
func fieldTypeName(field *ast.Field) string {
	ft := types.ExprString(field.Type)
	switch ft {
	case "string":
		return "string"
	case "int":
		return "number"
	case "bool":
		return "boolean"
	case "time.Duration":
		return "duration"
	case "[]string":
		return "list of strings"
	case "float64", "float32":
		return "float"
	default:
		switch {
		case strings.HasPrefix(ft, "[]"):
			return "list"
		case strings.HasPrefix(ft, "map["):
			return "map"
		default:
			return ft
		}
	}
}

func main() {
	err := generateFromStruct(filepath.Join("pkg", "config"))
	if err != nil {
		panic(err)
	}
}
