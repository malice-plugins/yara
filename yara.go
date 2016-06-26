package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/crackcomm/go-clitable"
	"github.com/hillu/go-yara"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
	r "gopkg.in/dancannon/gorethink.v2"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

const (
	name     = "yara"
	category = "av"
)

type pluginResults struct {
	ID   string      `json:"id" gorethink:"id,omitempty"`
	Data ResultsData `json:"yara" gorethink:"yara"`
}

// Yara json object
type Yara struct {
	Results ResultsData `json:"yara"`
}

// ResultsData json object
type ResultsData struct {
	Matches []yara.MatchRule `json:"matches" gorethink:"matches"`
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

// getSHA256 calculates a file's sha256sum
func getSHA256(name string) string {

	dat, err := ioutil.ReadFile(name)
	assert(err)

	h256 := sha256.New()
	_, err = h256.Write(dat)
	assert(err)

	return fmt.Sprintf("%x", h256.Sum(nil))
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

// TODO: handle more than just the first Offset, handle multiple MatchStrings
func printMarkDownTable(yara Yara) {
	fmt.Println("#### Yara")
	if yara.Results.Matches != nil {
		table := clitable.New([]string{"Rule", "Description", "Offset", "Data", "Tags"})
		for _, match := range yara.Results.Matches {
			var tags string
			if len(match.Tags) == 0 {
				tags = ""
			} else {
				tags = match.Tags[0]
			}
			table.AddRow(map[string]interface{}{
				"Rule":        match.Rule,
				"Description": match.Meta["description"],
				"Offset":      match.Strings[0].Offset,
				"Data":        string(match.Strings[0].Data),
				"Tags":        tags,
			})
		}
		table.Markdown = true
		table.Print()
	} else {
		fmt.Println(" - No Matches")
	}
}

// scanFile scans file with all yara rules in the rules folder
func scanFile(path string, rulesDir string) ResultsData {
	yaraResults := ResultsData{}

	fileList := []string{}
	err := filepath.Walk(rulesDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return nil
	})
	assert(err)

	comp, err := yara.NewCompiler()
	assert(err)

	for _, file := range fileList {
		// fmt.Println(file)
		f, err := os.Open(file)
		assert(err)
		comp.AddFile(f, "malice")
		f.Close()
	}

	r, err := comp.GetRules()

	// args: filename string, flags ScanFlags, timeout time.Duration
	matches, err := r.ScanFile(path, 0, 60)
	assert(err)
	yaraResults.Matches = matches
	// fmt.Printf("Matches: %+v", matches)
	return yaraResults
}

// writeToDatabase upserts plugin results into Database
func writeToDatabase(results pluginResults) {

	address := fmt.Sprintf("%s:28015", getopt("MALICE_RETHINKDB", "rethink"))

	// connect to RethinkDB
	session, err := r.Connect(r.ConnectOpts{
		Address:  address,
		Timeout:  5 * time.Second,
		Database: "malice",
	})
	defer session.Close()

	if err == nil {
		res, err := r.Table("samples").Get(results.ID).Run(session)
		assert(err)
		defer res.Close()

		if res.IsNil() {
			// upsert into RethinkDB
			resp, err := r.Table("samples").Insert(results, r.InsertOpts{Conflict: "replace"}).RunWrite(session)
			assert(err)
			log.Debug(resp)
		} else {
			resp, err := r.Table("samples").Get(results.ID).Update(map[string]interface{}{
				"plugins": map[string]interface{}{
					category: map[string]interface{}{
						name: results.Data,
					},
				},
			}).RunWrite(session)
			assert(err)

			log.Debug(resp)
		}

	} else {
		log.Debug(err)
	}
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
	var rules string
	var table bool
	var rethinkdb string
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "rethinkdb",
			Value:       "",
			Usage:       "rethinkdb address for Malice to store results",
			EnvVar:      "MALICE_RETHINKDB",
			Destination: &rethinkdb,
		},
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
		cli.StringFlag{
			Name:        "rules",
			Value:       "/rules",
			Usage:       "YARA rules directory",
			Destination: &rules,
		},
	}
	app.ArgsUsage = "FILE to scan with YARA"
	app.Action = func(c *cli.Context) error {
		if c.Args().Present() {
			path := c.Args().First()
			// Check that file exists
			if _, err := os.Stat(path); os.IsNotExist(err) {
				assert(err)
			}
			if c.Bool("verbose") {
				log.SetLevel(log.DebugLevel)
			}
			yara := Yara{Results: scanFile(path, rules)}

			// upsert into Database
			writeToDatabase(pluginResults{ID: getSHA256(path), Data: yara.Results})

			if table {
				printMarkDownTable(yara)
			} else {
				yaraJSON, err := json.Marshal(yara)
				assert(err)
				fmt.Println(string(yaraJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a file to scan with YARA"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
