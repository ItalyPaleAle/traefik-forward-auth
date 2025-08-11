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
	"strconv"
	"strings"
)

const (
	docsFileDest = "docs/03-all-configuration-options.md"
)

var structTypes map[string]*ast.StructType

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

	// Map to store struct types defined in the file
	structTypes = make(map[string]*ast.StructType)

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

		processStruct(structType, "", "", "", outYAML, outMD)
		return false
	})

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
func processStruct(structType *ast.StructType, yamlPrefix string, parentYamlPath string, sectionName string, outYAML io.Writer, outMD io.Writer) {
	y := func(format string, a ...any) { fmt.Fprintf(outYAML, yamlPrefix+format, a...) }

	if parentYamlPath == "" {
		switch sectionName {
		case "":
			printMarkdownHeader("Root configuration object", outMD)
		case "portals":
			fmt.Fprint(outMD, "\n")
			printMarkdownHeader("Portal configuration", outMD)
		case "providers":
			fmt.Fprint(outMD, "\n")
			printMarkdownHeader("Provider configuration", outMD)
		}
	}

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

		// Handle the special "portals" field
		if fullYamlPath == "portals" && sectionName == "" {
			processPortalsField(outYAML, outMD, yamlPrefix)
			continue
		}

		// Handle the special "providers" field
		if fullYamlPath == "providers" && sectionName == "portals" {
			processProvidersField(outYAML, outMD, yamlPrefix)
			continue
		}

		// Handle regular (non-struct) fields
		if !isStructField {
			processField(field, fullYamlPath, sectionName, outYAML, outMD, yamlPrefix)
			continue
		}

		// Process nested struct
		nestedStruct := structTypes[structName]
		if nestedStruct != nil {
			// Only output a header for this struct if it's not the root
			if parentYamlPath != "" {
				y("## %s\n", fullYamlPath)
				if field.Doc != nil && field.Doc.Text() != "" {
					y("## Description:\n")
					for _, line := range strings.Split(field.Doc.Text(), "\n") {
						if line != "" {
							y("##   %s\n", line)
						}
					}
				}
				// Generate proper YAML indentation for nested structures
				y("%s:\n", yamlTag)
			} else {
				// For top-level fields
				y("%s:\n", yamlTag)
			}

			// Process nested fields with appropriate indentation
			processStruct(nestedStruct, yamlPrefix+"  ", fullYamlPath, sectionName, outYAML, outMD)
		}
	}
}

// processField handles a single field, generating documentation
func processField(field *ast.Field, yamlTag string, sectionName string, outYAML io.Writer, outMD io.Writer, yamlPrefix string) {
	var (
		defaultText, doc, example, value string
		required, recommended, lastEmpty bool
	)

	y := func(format string, a ...any) { fmt.Fprintf(outYAML, yamlPrefix+format, a...) }

	// Get the last part of the YAML path for field name (after the last dot)
	fieldName := yamlTag
	if idx := strings.LastIndex(yamlTag, "."); idx > -1 {
		fieldName = yamlTag[idx+1:]
	}

	// Field type
	typ := fieldTypeName(field)

	anchor := strings.ReplaceAll(yamlTag, ".", "-")
	if sectionName != "" {
		anchor = sectionName + "-" + anchor
	}

	// Parse field documentation
	y("## %s (%s)\n", yamlTag, typ)
	fmt.Fprintf(outMD, "| <a id=\"config-opt-%s\"></a>`%s` | %s | ", strings.ToLower(anchor), yamlTag, typ)
	if field.Doc != nil {
		doc = field.Doc.Text()
	}
	var mdFooter string
	if doc != "" {
		y("## Description:\n")
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
			case strings.HasPrefix(line, "+example "):
				example = strings.TrimPrefix(line, "+example ")
			default:
				if lastEmpty {
					y("##\n")
					fmt.Fprint(outMD, "<br>")
				}
				y("##   %s\n", line)
				if i > 0 {
					fmt.Fprint(outMD, "<br>"+line)
				} else {
					fmt.Fprint(outMD, line)
				}
				lastEmpty = false
			}
		}

		if defaultText != "" {
			y("## Default: %s\n", defaultText)
			mdFooter = "Default: _" + defaultText + "_"
		}
	}

	// Get the value to show
	value = defaultText
	if value == "" {
		if example != "" {
			value = example
		} else {
			value = defaultValueForType(field.Type)
		}
	}

	if required {
		y("## Required\n")
		y("%s: %s\n\n", fieldName, value)
		mdFooter = "**Required**"
	} else {
		if recommended {
			if mdFooter != "" {
				mdFooter = "Recommended<br>" + mdFooter
			} else {
				mdFooter = "Recommended"
			}
		}
		y("#%s: %s\n\n", fieldName, value)
	}
	fmt.Fprintf(outMD, "| %s |\n", mdFooter)
}

// processPortalsField handles the special "portals" field
func processPortalsField(outYAML io.Writer, outMD io.Writer, yamlPrefix string) {
	y := func(format string, a ...any) { fmt.Fprintf(outYAML, yamlPrefix+format, a...) }
	y("## portals (list of portals)\n")
	y("## Description:\n")
	y("##   List of portals\n")
	y("##   At least one configured portal and provider is required\n")
	y("portals:\n")
	y("  - ## Example portal configuration\n")
	y("    ## Configure the portal with the required fields and at least one provider\n\n")

	fmt.Fprintln(outMD, `| <a id="config-opt-portals"></a>`+"`portals`"+`| list of [portal configurations](#portal-configuration) | List of portals.<br>See the [portal configuration](#portal-configuration) section for more details. | **Required**<br>At least one configured portal and provider is required |`)

	processStruct(structTypes["ConfigPortal"], "    ", "", "portals", outYAML, outMD)
}

// processProvidersField handles the special "providers" field
func processProvidersField(outYAML io.Writer, outMD io.Writer, yamlPrefix string) {
	y := func(format string, a ...any) { fmt.Fprintf(outYAML, yamlPrefix+format, a...) }
	y("## providers (list of provider configurations)\n")
	y("## Description:\n")
	y("##   List of allowed authentication providers\n")
	y("##   At least one provider is required.\n")
	y("providers:\n")
	y("  - ## Example provider configuration\n\n")

	fmt.Fprintln(outMD, `| <a id="config-opt-providers"></a>`+"`providers`"+`| list of [provider configurations](#provider-configuration) | List of allowed authentication providers<br>See the [provider configuration](#provider-configuration) section for more details. | **Required**<br>At least one provider is required. |`)

	processStruct(structTypes["ConfigPortalProvider"], "        ", "", "providers", outYAML, outMD)
}

func printMarkdownHeader(header string, outMD io.Writer) {
	fmt.Fprintf(outMD, "## %s\n\n", header)
	fmt.Fprint(outMD, "| Name | Type | Description | |\n")
	fmt.Fprint(outMD, "| --- | --- | --- | --- |\n")
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

// defaultValueForType returns a simple example for a type (string placeholders)
func defaultValueForType(expr ast.Expr) string {
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
	case "[]string", "[]ConfigPortal":
		return "[]"
	default:
		return "" // unknown or nested
	}
}

func main() {
	err := generateFromStruct(filepath.Join("pkg", "config"))
	if err != nil {
		panic(err)
	}
}
