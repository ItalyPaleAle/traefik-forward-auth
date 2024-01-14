//nolint:forbidigo,errcheck
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
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
				typ, defaultText                 string
				required, recommended, lastEmpty bool
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
			fmt.Fprintf(outYAML, "## %s (%s)\n", yamlTag, typ)
			fmt.Fprintf(outMD, "| <a id=\"config-opt-%s\"></a>YAML: `%s`<br>Env: %s | %s | ", strings.ToLower(yamlTag), yamlTag, envTagMD, typ)
			doc := field.Doc.Text()
			var mdFooter string
			if doc != "" {
				fmt.Fprint(outYAML, "## Description:\n")
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
							fmt.Fprint(outYAML, "##\n")
							fmt.Fprint(outMD, "<br>")
						}
						fmt.Fprintf(outYAML, "##   %s\n", line)
						if i > 0 {
							fmt.Fprint(outMD, "<br>"+line)
						} else {
							fmt.Fprint(outMD, line)
						}
						lastEmpty = false
					}
				}

				if defaultText != "" {
					fmt.Fprintf(outYAML, "## Default: %s\n", defaultText)
					mdFooter = "Default: _" + defaultText + "_"
				}
			}

			if required {
				fmt.Fprintf(outYAML, "## Required\n%s:\n\n", yamlTag)
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
				fmt.Fprintf(outYAML, "#%s: \n\n", yamlTag)
			}
			fmt.Fprintf(outMD, "| %s |\n", mdFooter)
		}

		return false
	})

	// Replace the configuration table in the README.md file
	readme, err := os.ReadFile("README.md")
	if err != nil {
		return err
	}

	const (
		beginMarker = "<!-- BEGIN CONFIG TABLE -->"
		endMarker   = "<!-- END CONFIG TABLE -->"
	)
	begin := bytes.Index(readme, []byte(beginMarker)) + len(beginMarker)
	end := bytes.Index(readme, []byte(endMarker))

	readmeFile, err := os.Create("README.md")
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

func main() {
	err := generateFromStruct("pkg/config/config.go")
	if err != nil {
		panic(err)
	}
}
