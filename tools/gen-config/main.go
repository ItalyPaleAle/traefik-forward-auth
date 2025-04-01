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
	envPrefix    = "TFA_"
)

// Struct to hold information about a field
type fieldInfo struct {
	yamlTag     string
	envTag      string
	typ         string
	doc         string
	defaultText string
	required    bool
	recommended bool
}

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
		typ, defaultText                 string
		required, recommended, lastEmpty bool
	)

	// Get the last part of the YAML path for field name (after the last dot)
	fieldName := yamlTag
	if idx := strings.LastIndex(yamlTag, "."); idx > -1 {
		fieldName = yamlTag[idx+1:]
	}

	// Field type
	ft := types.ExprString(field.Type)
	switch ft {
	case "string":
		typ = "string"
	case "int":
		typ = "number"
	case "bool":
		typ = "boolean"
	case "time.Duration":
		typ = "duration"
	case "[]string":
		typ = "list of strings"
	case "float64", "float32":
		typ = "float"
	default:
		if strings.HasPrefix(ft, "[]") {
			typ = "list"
		} else if strings.HasPrefix(ft, "map[") {
			typ = "map"
		} else {
			typ = ft
		}
		fmt.Printf("WARN: non-primitive type for field '%s': %s\n", yamlTag, ft)
	}

	// Parse field documentation
	envTagMD := "-"
	if envTag != "" && envTag != "-" {
		envTagMD = "`" + envPrefix + envTag + "`"
	}
	fmt.Fprintf(outYAML, "%s## %s (%s)\n", prefix, yamlTag, typ)
	fmt.Fprintf(outMD, "| <a id=\"config-opt-%s\"></a>YAML: `%s`<br>Env: %s | %s | ", strings.ToLower(strings.ReplaceAll(yamlTag, ".", "-")), yamlTag, envTagMD, typ)
	doc := ""
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

func main() {
	err := generateFromStruct(filepath.Join("pkg", "config", "config.go"))
	if err != nil {
		panic(err)
	}
}
