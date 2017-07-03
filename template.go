package main

const tpl = `#### Yara
{{- if .Results.Matches}}
| Rule        | Description  | Offset      | Data        | Tags        |
|-------------|--------------|-------------|-------------|-------------|
{{range .Results.Matches}}
| {{ .Rule }} | {{ index .Meta "description" }} | {{ (index .Strings 0).Offset }} | ` + "`" + `{{ index .Strings.Data 0 }}` + "`" + ` | {{ index .Tags 0 }} |
{{- end }}
{{ end -}}
`
