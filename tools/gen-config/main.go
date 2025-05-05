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
	envPrefix    = "TFA_"
)

func generateFromStruct(filePath string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
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
	providerFilePath := filepath.Join(filepath.Dir(filePath), "providers-config.go")
	err = generatePortalExamples(outYAML, providerFilePath)
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
		envTag, _ := tags.Lookup("env")
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
			processField(field, fullYamlPath, envTag, outYAML, outMD, prefix)
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
func processField(field *ast.Field, yamlTag string, envTag string, outYAML io.Writer, outMD io.Writer, prefix string) {
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
	envTagMD := "-"
	if envTag != "" && envTag != "-" {
		envTagMD = "`" + envPrefix + envTag + "`"
	}
	fmt.Fprintf(outYAML, "%s## %s (%s)\n", prefix, yamlTag, typ)
	fmt.Fprintf(outMD, "| <a id=\"config-opt-%s\"></a>YAML: `%s`<br>Env: %s | %s | ", strings.ToLower(strings.ReplaceAll(yamlTag, ".", "-")), yamlTag, envTagMD, typ)
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
	fmt.Fprintf(outYAML, "### Example Portal Configurations\n")
	fmt.Fprintf(outYAML, "### The following are examples of portal configurations with different providers\n\n")

	// Start the portals list with proper indentation
	fmt.Fprintf(outYAML, "portals:\n")

	// Parse the providers file to extract struct definitions
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, providerFilePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	// Map to collect provider structs and their fields
	providerTypes := make(map[string]*struct {
		structType   *ast.StructType
		displayName  string
		providerType string
		doc          string
	})
	providerNames := make([]string, 0)

	// First pass: collect all provider struct types
	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		// Look for provider config structs that match the pattern ProviderConfig_*
		typeName := typeSpec.Name.Name
		if strings.HasPrefix(typeName, "ProviderConfig_") {
			providerType := strings.TrimPrefix(typeName, "ProviderConfig_")

			// Get documentation from comments
			doc := ""
			if typeSpec.Doc != nil {
				doc = typeSpec.Doc.Text()
			}

			// Add to our collection
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

	// Generate example for each provider type
	slices.Sort(providerNames)
	for _, k := range providerNames {
		provider := providerTypes[k]
		generateProviderExample(outYAML, provider.structType, provider.providerType, provider.displayName)
	}

	return nil
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

// getProviderDisplayName converts the struct name to the actual provider display name used in configuration
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

// generateProviderExample creates a YAML example for a single provider
func generateProviderExample(outYAML io.Writer, structType *ast.StructType, providerType string, displayName string) {
	portalName := providerType + "-portal"
	displayTitle := displayName + " Authentication"

	fmt.Fprintf(outYAML, "  # Example portal using %s authentication\n", displayName)
	fmt.Fprintf(outYAML, "  - name: %s\n", portalName)
	fmt.Fprintf(outYAML, "    displayName: \"%s\"\n", displayTitle)
	fmt.Fprintf(outYAML, "    authenticationTimeout: 5m\n")
	fmt.Fprintf(outYAML, "    providers:\n")
	fmt.Fprintf(outYAML, "      - provider: %s\n", providerType)
	fmt.Fprintf(outYAML, "        # Default name is the provider type\n")
	fmt.Fprintf(outYAML, "        name: \"\"\n")
	fmt.Fprintf(outYAML, "        # Optional display name; if empty, uses the default value for the provider type\n")
	fmt.Fprintf(outYAML, "        displayName: \"\"\n")
	fmt.Fprintf(outYAML, "        # Optional icon; if empty, uses the default value for the provider type\n")
	fmt.Fprintf(outYAML, "        icon: \"\"\n")
	fmt.Fprintf(outYAML, "        # Optional color scheme; if empty, uses the default value for the provider type\n")
	fmt.Fprintf(outYAML, `        # Supported values: "purple-to-blue", "cyan-to-blue", "green-to-blue", "purple-to-pink", "pink-to-orange", "teal-to-lime", "red-to-yellow"`+"\n")
	fmt.Fprintf(outYAML, "        color: \"\"\n")
	fmt.Fprintf(outYAML, "        # Provider configuration\n")
	fmt.Fprintf(outYAML, "        config:\n")

	// Process fields from the struct
	fieldPrefix := strings.Repeat(" ", 10)
	for _, field := range structType.Fields.List {
		var (
			defaultText, doc, examplePrefix string
			required, lastEmpty             bool
		)

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

		// Extract field docs to determine requirements and defaults
		if field.Doc != nil {
			doc = field.Doc.Text()
		}

		// Field type
		typ := fieldTypeName(field)

		// Print field name and type
		fmt.Fprintf(outYAML, "          ## %s (%s)\n", yamlTag, typ)

		// Add comments from field documentation
		if doc != "" {
			fmt.Fprint(outYAML, "          ## Description:\n")
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
					// Nothing to do here in example generation
				default:
					if lastEmpty {
						fmt.Fprintf(outYAML, "%s##\n", fieldPrefix)
					}
					fmt.Fprintf(outYAML, "%s##   %s\n", fieldPrefix, line)
					lastEmpty = false
				}
			}

			if defaultText != "" {
				fmt.Fprintf(outYAML, "%s## Default: %s\n", fieldPrefix, defaultText)
			}

			if required {
				fmt.Fprintf(outYAML, "%s## Required\n", fieldPrefix)
			}
		}

		// Generate example value based on field type
		examplePrefix = fieldPrefix
		if !required {
			examplePrefix += "# "
		}
		exampleValue := generateExampleValue(field.Type, yamlTag, providerType, examplePrefix)

		if exampleValue != "" {
			if strings.HasPrefix(exampleValue, "\n") {
				// For list/complex types that include newlines
				fmt.Fprintf(outYAML, "%s%s:%s\n\n", examplePrefix, yamlTag, exampleValue)
			} else {
				fmt.Fprintf(outYAML, "%s%s: %s\n\n", examplePrefix, yamlTag, exampleValue)
			}
		}
	}
	// fmt.Fprintf(outYAML, "\n")
}

// generateExampleValue creates an appropriate example value based on field type
func generateExampleValue(fieldType ast.Expr, fieldName string, providerType string, fieldPrefix string) string {
	ft := types.ExprString(fieldType)

	// Special cases based on field name and provider
	if fieldName == "clientID" {
		switch providerType {
		case "google":
			return `"your-google-client-id.apps.googleusercontent.com"`
		default:
			return `"your-client-id"`
		}
	}

	if fieldName == "clientSecret" {
		return `"your-client-secret"`
	}

	if fieldName == "tenantID" && providerType == "microsoftentraid" {
		return `"your-tenant-id"`
	}

	if fieldName == "tokenIssuer" && providerType == "openidconnect" {
		return `"https://your-identity-provider/.well-known/openid-configuration"`
	}

	if fieldName == "allowedTailnet" && providerType == "tailscalewhois" {
		return `"yourtailnet.ts.net"`
	}

	if fieldName == "azureFederatedIdentity" && providerType == "microsoftentraid" {
		return `"ManagedIdentity"`
	}

	// Handle by type
	switch ft {
	case "string":
		return `"example-value"`
	case "int":
		return "123"
	case "bool":
		if fieldName == "enablePKCE" {
			return "true"
		}
		return "false"
	case "time.Duration":
		return "10s"
	case "[]string":
		switch fieldName {
		case "allowedUsers":
			switch providerType {
			case "github":
				return "\n" + fieldPrefix + "  - \"githubuser1\"\n" + fieldPrefix + "  - \"githubuser2\""
			case "microsoftentraid":
				return "\n" + fieldPrefix + "  - \"user-object-id\""
			case "tailscalewhois":
				return "\n" + fieldPrefix + "  - \"user@example.com\""
			default:
				return "\n" + fieldPrefix + "  - \"user1\"\n" + fieldPrefix + "  - \"user2\""
			}
		case "allowedEmails":
			return "\n" + fieldPrefix + "  - \"user@example.com\""
		case "allowedDomains":
			return "\n" + fieldPrefix + "  - \"yourdomain.com\""
		default:
			return "\n" + fieldPrefix + "  - \"example1\"\n" + fieldPrefix + "  - \"example2\""
		}
	default:
		return ""
	}
}

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
	err := generateFromStruct(filepath.Join("pkg", "config", "config.go"))
	if err != nil {
		panic(err)
	}
}
