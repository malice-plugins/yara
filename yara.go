package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/crackcomm/go-clitable"
	"github.com/hillu/go-yara"
	"github.com/parnurzeal/gorequest"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

// Yara json object
type Yara struct {
	Results ResultsData `json:"yara"`
}

// ResultsData json object
type ResultsData struct {
	Matches []yara.MatchRule `json:"matches"`
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

// TODO: handle more than just the first Offset, handle multiple MatchStrings
func printMarkDownTable(yara Yara) {
	fmt.Println("#### yara")
	table := clitable.New([]string{"Rule", "Description", "Offset", "Data"})
	for _, match := range yara.Results.Matches {
		table.AddRow(map[string]interface{}{
			"Rule":        match.Rule,
			"Description": match.Meta["description"],
			"Offset":      match.Strings[0].Offset,
			"Data":        string(match.Strings[0].Data),
		})
	}
	table.Markdown = true
	table.Print()
}

// scanFile scans file with all yara rules in the rules folder
func scanFile(path string, apikey string) ResultsData {
	yaraResults := ResultsData{}
	return yaraResults
}

var appHelpTemplate = `Usage: {{.Name}} {{if .Flags}}[OPTIONS] {{end}}COMMAND [arg...]

{{.Usage}}

Version: {{.Version}}{{if or .Author .Email}}

Author:{{if .Author}}
  {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
  {{.Email}}{{end}}{{end}}
{{if .Flags}}
Options:
  {{range .Flags}}{{.}}
  {{end}}{{end}}
Commands:
  {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}
Run '{{.Name}} COMMAND --help' for more information on a command.
`

func main() {
	cli.AppHelpTemplate = appHelpTemplate
	app := cli.NewApp()
	app.Name = "yara"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice YARA Plugin"
	var apikey string
	var table bool
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   "post, p",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.BoolFlag{
			Name:        "table, t",
			Usage:       "output as Markdown table",
			Destination: &table,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "scan",
			Aliases:   []string{"s"},
			Usage:     "Scan file with YARA",
			ArgsUsage: "FILE to scan with YARA",
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					path := c.Args().First()
					// Check that file exists
					if _, err := os.Stat(path); os.IsNotExist(err) {
						assert(err)
					}
					scanFile(path, apikey)
				} else {
					log.Fatal(fmt.Errorf("Please supply a file to scan with YARA"))
				}
			},
		},
	}

	err := app.Run(os.Args)
	assert(err)
}
