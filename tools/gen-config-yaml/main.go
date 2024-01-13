//nolint:forbidigo
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
)

func generateYAMLFromStruct(filePath string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	outFile, err := os.Create("config.sample.yaml")
	if err != nil {
		return err
	}
	defer outFile.Close()

	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Config" {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		for _, field := range structType.Fields.List {
			unquoted, _ := strconv.Unquote(field.Tag.Value)
			tags := reflect.StructTag(unquoted)
			yamlTag, ok := tags.Lookup("yaml")
			if !ok || yamlTag == "" || yamlTag == "-" {
				continue
			}

			var (
				typ, defaultText    string
				required, lastEmpty bool
			)

			// Field type
			switch fmt.Sprintf("%s", field.Type) {
			case "string":
				typ = "string"
			case "int":
				typ = "number"
			case "bool":
				typ = "boolean"
			case "&{time Duration}":
				typ = "duration"
			default:
				fmt.Printf("WARN: unknown type for field '%s': %s\n", yamlTag, field.Type)
			}

			// Parse field documentation
			fmt.Fprintf(outFile, "## %s (%s)\n", yamlTag, typ)
			doc := field.Doc.Text()
			if doc != "" {
				fmt.Fprint(outFile, "## Description:\n")
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
					default:
						if lastEmpty {
							fmt.Fprint(outFile, "##\n")
						}
						fmt.Fprintf(outFile, "##   %s\n", line)
						lastEmpty = false
					}
				}

				if defaultText != "" {
					fmt.Fprintf(outFile, "## Default: %s\n", defaultText)
				}
			}

			if required {
				fmt.Fprintf(outFile, "## Required\n%s:\n\n", yamlTag)
			} else {
				fmt.Fprintf(outFile, "#%s: \n\n", yamlTag)
			}
		}

		return false
	})

	return nil
}

func main() {
	err := generateYAMLFromStruct("pkg/config/config.go")
	if err != nil {
		panic(err)
	}
}
