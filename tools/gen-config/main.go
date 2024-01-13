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

func generateFromStruct(filePath string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	outFileYAML, err := os.Create("config.sample.yaml")
	if err != nil {
		return err
	}
	defer outFileYAML.Close()

	outFileMD, err := os.Create("config.md")
	if err != nil {
		return err
	}
	defer outFileMD.Close()
	fmt.Fprint(outFileMD, "| YAML option | Environmental variable | Type | Description | Default value | Required |\n")
	fmt.Fprint(outFileMD, "| --- | --- | --- | --- | --- | --- |\n")

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
			envTag, _ := tags.Lookup("env")
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
			envTagMD := "-"
			if envTag != "" && envTag != "-" {
				envTagMD = "`TFA_" + envTag + "`"
			}
			fmt.Fprintf(outFileYAML, "## %s (%s)\n", yamlTag, typ)
			fmt.Fprintf(outFileMD, "| `%s` | %s | %s | ", yamlTag, envTagMD, typ)
			doc := field.Doc.Text()
			if doc != "" {
				fmt.Fprint(outFileYAML, "## Description:\n")
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
							fmt.Fprint(outFileYAML, "##\n")
							fmt.Fprint(outFileMD, "<br>")
						}
						fmt.Fprintf(outFileYAML, "##   %s\n", line)
						fmt.Fprintf(outFileMD, "%s<br>", strings.ReplaceAll(line, "\n", "<br>"))
						lastEmpty = false
					}
				}

				if defaultText != "" {
					fmt.Fprintf(outFileYAML, "## Default: %s\n", defaultText)
					fmt.Fprintf(outFileMD, " | %s | ", defaultText)
				} else {
					fmt.Fprint(outFileMD, " | | ")
				}
			}

			if required {
				fmt.Fprintf(outFileYAML, "## Required\n%s:\n\n", yamlTag)
				fmt.Fprint(outFileMD, "**Required** |\n")
			} else {
				fmt.Fprintf(outFileYAML, "#%s: \n\n", yamlTag)
				fmt.Fprint(outFileMD, "|\n")
			}
		}

		return false
	})

	return nil
}

func main() {
	err := generateFromStruct("pkg/config/config.go")
	if err != nil {
		panic(err)
	}
}
