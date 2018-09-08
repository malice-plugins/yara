package main

// escaped data
const tpl = `#### Yara
{{- if .Results.Matches}}
| Rule        | Description  | Offset      | Data        | Tags        |
|-------------|--------------|-------------|-------------|-------------|
{{- range .Results.Matches }}
| ` + "`" + `{{ .Rule }}` + "`" + ` | {{ index .Meta "description" }} | ` + "`" + `{{ printf "%#x" (index .Strings 0).Offset }}` + "`" + ` | ` + "`" + `{{ printf "%.25q" (index .Strings 0).Data }}` + "`" + ` | {{ .Tags }} |
{{- end }}
> NOTE: **Data** truncated to 25 characters
{{ else }}
 - No Matches Found
{{- end }}
`

// code-ified escaped data
const tpl2 = `#### Yara
{{- if .Results.Matches}}
| Rule        | Description  | Offset      | Data        | Tags        |
|-------------|--------------|-------------|-------------|-------------|
{{- range .Results.Matches }}
| ` + "`" + `{{ .Rule }}` + "`" + ` | {{ index .Meta "description" }} | {{ (index .Strings 0).Offset }} | ` + "`" + `{{ printf "%#q" (index .Strings 0).Data }}` + "`" + ` | {{ .Tags }} |
{{- end }}
{{ end -}}
`
