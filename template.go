package main

const tpl = `#### Yara
{{- if .Results.Matches}}
| Rule        | Description  | Offset      | Data        | Tags        |
|-------------|--------------|-------------|-------------|-------------|
{{- range .Results.Matches }}
| ` + "`" + `{{ .Rule }}` + "`" + ` | {{ index .Meta "description" }} | {{ (index .Strings 0).Offset }} | ` + "`" + `{{ printf "%#q" (index .Strings 0).Data }}` + "`" + ` | {{ .Tags }} |
{{- end }}
{{ end -}}
`
