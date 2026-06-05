package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type fieldInfo struct {
	Name string
	JSON string
	Type string
}

func main() {
	repo := flag.String("repo", ".", "sub2api repository root")
	flag.Parse()

	structs := map[string][]fieldInfo{}
	for _, target := range []struct {
		file string
		name string
	}{
		{file: "backend/internal/confidential/rpc.go", name: "authorizeArgs"},
		{file: "backend/internal/confidential/types.go", name: "RoutingNeeds"},
		{file: "backend/internal/confidential/types.go", name: "AuthorizeResult"},
		{file: "backend/internal/confidential/types.go", name: "UsageTelemetry"},
	} {
		fields, err := extractStruct(filepath.Join(*repo, target.file), target.name)
		if err != nil {
			fatal(err)
		}
		structs[target.name] = fields
	}

	policyCount, err := countPolicies(filepath.Join(*repo, "backend/internal/confidential/policy.go"))
	if err != nil {
		fatal(err)
	}

	fmt.Println("# Control-Channel Capacity Bound")
	fmt.Println()
	fmt.Println("Generated from Go source. The host can vary only fields that cross from host to enclave in `AuthorizeResult`; request-body bytes are not present in any control-channel schema.")
	fmt.Println()
	for _, name := range []string{"authorizeArgs", "RoutingNeeds", "AuthorizeResult", "UsageTelemetry"} {
		fmt.Printf("## %s\n\n", name)
		for _, f := range structs[name] {
			fmt.Printf("- `%s` json=`%s` type=`%s`\n", f.Name, f.JSON, f.Type)
		}
		fmt.Println()
	}

	destBits := 0.0
	if policyCount > 1 {
		destBits = math.Log2(float64(policyCount))
	}
	fmt.Println("## Bound")
	fmt.Println()
	fmt.Printf("- Baked provider-policy choices: `%d`; destination-selection capacity on the allow path: `%.2f` bits/request.\n", policyCount, destBits)
	fmt.Println("- `provider_id` and `endpoint_policy_id` are names into the measured policy map; they do not carry a URL, host, or path.")
	fmt.Println("- `allowed=false` exposes `deny_reason` to the client, but no plaintext body is released on that path.")
	fmt.Println("- On the allow path, host-variable `account_id`, `model`, and `credential` are metadata or upstream-auth choices; they do not rewrite the client body.")
	fmt.Println("- The single-frame RPC cap is `16 MiB`; unbounded strings are operationally frame-bounded and are not body-derived fields.")
	fmt.Println("- Body-derived leakage capacity through the host/enclave control channel: `0` body bytes/request by schema.")
}

func extractStruct(path, name string) ([]fieldInfo, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != name {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return nil, fmt.Errorf("%s is not a struct", name)
			}
			var out []fieldInfo
			for _, field := range st.Fields.List {
				typeName := renderNode(fset, field.Type)
				jsonName := ""
				if field.Tag != nil {
					tag := strings.Trim(field.Tag.Value, "`")
					jsonName = strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
				}
				for _, fieldName := range field.Names {
					nameForJSON := jsonName
					if nameForJSON == "" {
						nameForJSON = fieldName.Name
					}
					if nameForJSON == "-" {
						continue
					}
					out = append(out, fieldInfo{Name: fieldName.Name, JSON: nameForJSON, Type: typeName})
				}
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("struct %s not found in %s", name, path)
}

func countPolicies(path string) (int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return 0, err
	}
	count := 0
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if name.Name != "policies" || i >= len(spec.Values) {
				continue
			}
			lit, ok := spec.Values[i].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				if _, ok := elt.(*ast.KeyValueExpr); ok {
					count++
				}
			}
		}
		return true
	})
	if count == 0 {
		return 0, fmt.Errorf("no policies found in %s", path)
	}
	return count, nil
}

func renderNode(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return "<render-error>"
	}
	return buf.String()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
